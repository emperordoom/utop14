(function () {
  "use strict";

  var nav = document.querySelector("[data-nav]");
  if (!nav) return;

  var toggle = nav.querySelector("[data-nav-toggle]");
  var menu = nav.querySelector("#primary-menu");
  if (!toggle || !menu) return;

  var mobileQuery = window.matchMedia("(max-width: 880px)");

  function isOpen() {
    return nav.getAttribute("data-open") === "true";
  }

  function setOpen(open) {
    nav.setAttribute("data-open", String(open));
    toggle.setAttribute("aria-expanded", String(open));
    toggle.setAttribute("aria-label", open ? "Close menu" : "Open menu");
  }

  function close() {
    if (isOpen()) setOpen(false);
  }

  toggle.addEventListener("click", function () {
    setOpen(!isOpen());
  });

  nav.addEventListener("click", function (event) {
    if (mobileQuery.matches && event.target.closest("a")) {
      close();
    }
  });

  document.addEventListener("click", function (event) {
    if (isOpen() && !nav.contains(event.target)) {
      close();
    }
  });

  document.addEventListener("focusin", function (event) {
    if (isOpen() && !nav.contains(event.target)) {
      close();
    }
  });

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && isOpen()) {
      close();
      toggle.focus();
    }
  });

  if (typeof mobileQuery.addEventListener === "function") {
    mobileQuery.addEventListener("change", function (event) {
      if (!event.matches) close();
    });
  } else if (typeof mobileQuery.addListener === "function") {
    mobileQuery.addListener(function (event) {
      if (!event.matches) close();
    });
  }

  nav.setAttribute("data-enhanced", "true");
  toggle.hidden = false;
  setOpen(false);
})();
