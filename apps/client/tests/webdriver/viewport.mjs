// Android WebView.draw(Canvas) returns a blank PNG when the page is hidden,
// even with a non-zero viewport and a real DOM behind it.
export const laidOutAndVisible = value => Array.isArray(value) && value[0] > 0 && value[1] > 0 && value[2] === 'visible';
