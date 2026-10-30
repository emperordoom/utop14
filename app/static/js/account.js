/* Confirmation prompt for removing an account avatar. */
(() => {
  "use strict";

  const confirmedForms = new WeakSet();

  document.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) {
      return;
    }

    const form = event.target.closest("form[data-confirm]");
    if (!(form instanceof HTMLFormElement)) {
      return;
    }

    const message = form.dataset.confirm?.trim();
    if (!message) {
      return;
    }

    if (window.confirm(message)) {
      confirmedForms.add(form);
      return;
    }

    event.preventDefault();
    event.stopPropagation();
  });

  document.addEventListener(
    "submit",
    (event) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) {
        return;
      }
      if (confirmedForms.has(form)) {
        confirmedForms.delete(form);
        return;
      }
      const message = form.dataset.confirm?.trim();
      if (message && !window.confirm(message)) {
        event.preventDefault();
      }
    },
    true,
  );
})();
