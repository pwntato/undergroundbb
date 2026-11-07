package handlers

import (
	"net/http"
	"time"

	"github.com/pwntato/undergroundbb/internal/idgen"
)

// unreadCountTimeout bounds the whole count in GET /api/groups. The time budget below is only checked
// between batches, and each distinct unread post costs a read inside a batch, so a slow table could
// outlast the Lambda timeout and fail the list. With a deadline the overrun is an ordinary error, and
// the list is returned without counts. A variable so a test can shrink it.
var unreadCountTimeout = 5 * time.Second

// maxUnreadShown is the largest unread count reported for one group; one more sets UnreadMore, and
// the client shows "99+" (#145).
const maxUnreadShown = 99

// unreadCounts counts the caller's unread notifications per group, for GET /api/groups (#145).
// It reads the same descending NOTIF# range as the list, in the same batches and under the same
// pass and time limits, and counts a row only when the list would show it: the caller is in the
// group and the post is live. Rows already read cost nothing beyond the read that returned them.
// DynamoDB bills each row examined, so the work is bounded by the limits and by retention (TTL),
// not by a counter that every notification write and mark-read would have to keep exact.
//
// more holds the groups whose count is only a lower bound: the group passed maxUnreadShown, or the
// read stopped on a limit before the range ended and the group has some unread found.
func (h *Handler) unreadCounts(r *http.Request, userID string, memberOf map[string]bool) (counts map[string]int, more map[string]bool, err error) {
	counts = map[string]int{}
	more = map[string]bool{}
	f := &notificationFilter{h: h, r: r, userID: userID, now: time.Now(), member: memberOf, post: map[string]bool{}}
	started := time.Now()
	after := ""
	for pass := 0; pass < notificationMaxPasses; pass++ {
		// The last pass asks for one row more: a Query that uses its whole Limit returns a
		// LastEvaluatedKey even when nothing is left, so exactly 1000 rows would look unfinished
		// and show "1+" for a count that is exact.
		batch := notificationReadBatch
		if pass == notificationMaxPasses-1 {
			batch++
		}
		rows, last, done, err := h.db.ListNotifications(r.Context(), userID, after, batch)
		if err != nil {
			return nil, nil, err
		}
		for _, n := range rows {
			if n.Read || more[n.GroupID] {
				continue
			}
			// A group the caller is not in is dropped here, so keep() never looks it up again.
			if _, _, ok := idgen.ParsePostID(n.PostID); !ok || !memberOf[n.GroupID] {
				continue
			}
			keep, err := f.keep(n)
			if err != nil {
				return nil, nil, err
			}
			if !keep {
				continue
			}
			if counts[n.GroupID] == maxUnreadShown {
				more[n.GroupID] = true
				continue
			}
			counts[n.GroupID]++
		}
		if done {
			return counts, more, nil
		}
		after = last
		if time.Since(started) > notificationTimeBudget {
			break
		}
	}
	// Stopped on a limit: a count above zero is a lower bound. A group with none found gets no
	// flag, or every group would show a badge, and reading everything would not clear it (read
	// rows are what fill the window).
	for g, n := range counts {
		if n > 0 {
			more[g] = true
		}
	}
	return counts, more, nil
}
