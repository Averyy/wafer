// Fix CDP Input.dispatchMouseEvent setting screenX=clientX instead of
// offsetting by window position (Chromium bug #40280325).
// Runs in MAIN world so the patched getters are visible to page JS.
(function () {
  const origScreenX = Object.getOwnPropertyDescriptor(MouseEvent.prototype, 'screenX');
  const origScreenY = Object.getOwnPropertyDescriptor(MouseEvent.prototype, 'screenY');

  for (const cls of [MouseEvent, PointerEvent]) {
    Object.defineProperty(cls.prototype, 'screenX', {
      get() {
        const val = origScreenX.get.call(this);
        if (val === this.clientX) return val + (window.screenX || 0);
        return val;
      }
    });
    Object.defineProperty(cls.prototype, 'screenY', {
      get() {
        const val = origScreenY.get.call(this);
        if (val === this.clientY)
          return val + (window.screenY || 0) + (window.outerHeight - window.innerHeight);
        return val;
      }
    });
  }
})();
