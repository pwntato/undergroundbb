// Rewrites any extensionless request path to /index.html at the viewer-request
// stage, before CloudFront picks an origin. Attached to the default (frontend)
// cache behavior only -- see cloudfront.tf's comment on why this replaces
// custom_error_response for SPA fallback: rewriting here means S3 never sees
// a client-side route like /groups/abc in the first place, so there's no
// origin error for a distribution-wide error response to misroute onto /api/*.
//
// request.uri is the path only -- CloudFront Functions splits the querystring
// into request.querystring separately, so a "?" or "#" in the original request
// never reaches this function and doesn't need handling here.
//
// "Extensionless" is approximated as "no dot in the final path segment" --
// true for every client-side route (/groups/abc, /settings) and every real
// static file this bucket serves (favicon.svg, and everything under
// /assets/* has a hashed filename with an extension). Two known false
// positives, neither worth changing the heuristic over:
//   - A future static asset added without an extension would be misrouted to
//     index.html by this same rule; none exist today.
//   - A client-side route with a dot in its last segment (e.g. a username-
//     bearing path like /users/jimmy.hendrix, or /groups/v1.2) is treated as
//     a static file and falls through unrewritten, landing on S3's 403
//     instead of the SPA shell. DESIGN.md's routes are the likelier source
//     of this than the missing-extension case above.
//
// Explicit /api early return (round 2 review): /api/* is its own cache
// behavior targeting the Lambda origin, and behavior selection already keeps
// this function off of it for every path *under* /api/ -- but "/api/*" does
// not match the bare path "/api" (no trailing slash), which falls through to
// this, the default behavior, and gets rewritten to /index.html and served
// from S3 instead of the Lambda. Guarding here makes the invariant local to
// the function rather than an emergent property of behavior-pattern
// ordering -- belt-and-braces with the association scoping in cloudfront.tf,
// deliberately, since the two controls fail independently.
function handler(event) {
  var request = event.request;
  var uri = request.uri;

  if (uri === "/api" || uri.indexOf("/api/") === 0) {
    return request;
  }

  var lastSegment = uri.slice(uri.lastIndexOf("/") + 1);

  if (lastSegment.indexOf(".") === -1) {
    request.uri = "/index.html";
  }

  return request;
}
