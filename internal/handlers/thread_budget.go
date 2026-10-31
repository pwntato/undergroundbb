package handlers

import (
	"strings"

	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/models"
)

// defaultThreadBudget is the most JSON a thread page may weigh, comments and
// reactions together. A Lambda's synchronous response is limited to 6 MB; this
// leaves room for encoding and for the estimate being rough.
const defaultThreadBudget = 4 << 20

func (h *Handler) threadBudgetBytes() int {
	if h.threadBudget > 0 {
		return h.threadBudget
	}
	return defaultThreadBudget
}

// The wire size of one entry is its fields' base64 lengths plus a constant for
// the keys, quotes and commas. The constants are generous, and a test checks
// each estimate against the real JSON, so the budget errs on the safe side.
const (
	commentEntryOverhead  = 160
	reactionEntryOverhead = 112
)

func base64Len(n int) int { return 4 * ((n + 2) / 3) }

func commentWireSize(c models.Comment) int {
	return commentEntryOverhead + len(c.SK) + len(c.AuthorUserID) + len(c.SignedDay) +
		base64Len(len(c.Nonce)) + base64Len(len(c.Ciphertext)) + base64Len(len(c.Signature))
}

func reactionWireSize(x models.Reaction) int {
	return reactionEntryOverhead + len(x.SK) + base64Len(len(x.Nonce)) + base64Len(len(x.Ciphertext))
}

// fitThreadPage decides how much of a page goes out: it returns how many of the
// comments, and how many of the reactions, fit the budget. Reactions arrive in
// the thread's order (the reads' ranges guarantee it), so a prefix of the
// comments owns a prefix of the reactions: those whose sort key is at or before
// "RXN#<last kept path>$". The comments after the cut are not lost, because the
// caller's cursor continues from the last one kept, and neither are their
// reactions, which the next page reads along with them.
//
// The first comment is always kept, so every page makes progress, and so are
// the post's own reactions on the first page: nothing here can split what
// belongs to one target.
func fitThreadPage(comments []models.Comment, reactions []models.Reaction, budget int) (keepComments, keepReactions int) {
	if len(comments) == 0 {
		return 0, len(reactions)
	}
	total, j := 0, 0
	for i, c := range comments {
		upTo := db.ReactionSortKeyPrefix + strings.TrimPrefix(c.SK, db.CommentSortKeyPrefix) + "$"
		cost, k := commentWireSize(c), j
		for k < len(reactions) && reactions[k].SK <= upTo {
			cost += reactionWireSize(reactions[k])
			k++
		}
		if i > 0 && total+cost > budget {
			return i, j
		}
		total += cost
		j = k
	}
	return len(comments), len(reactions)
}
