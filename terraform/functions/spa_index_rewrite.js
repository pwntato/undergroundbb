// Rewrites any extensionless request path to /index.html at the viewer-request
// stage, before CloudFront picks an origin. Attached to the default (frontend)
// cache behavior only -- see cloudfront.tf's comment on why this replaces
// custom_error_response for SPA fallback: rewriting here means S3 never sees
// a client-side route like /groups/abc in the first place, so there's no
// origin error for a distribution-wide error response to misroute onto /api/*.
//
// "Extensionless" is approximated as "no dot in the final path segment" --
// true for every client-side route (/groups/abc, /settings) and every real
// static file this bucket serves (favicon.svg, and everything under
// /assets/* has a hashed filename with an extension). A future static asset
// added without an extension would be misrouted to index.html by this same
// rule; none exist today.
function handler(event) {
  var request = event.request;
  var uri = request.uri;
  var lastSegment = uri.slice(uri.lastIndexOf("/") + 1);

  if (lastSegment.indexOf(".") === -1) {
    request.uri = "/index.html";
  }

  return request;
}
