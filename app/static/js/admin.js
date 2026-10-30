/* Confirmation prompts for destructive or stock-changing admin actions. */
(() => {
  "use strict";

  const confirmedForms = new WeakSet();

  document.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) {
      return;
    }

    const trigger = event.target.closest("[data-confirm]");
    if (!(trigger instanceof HTMLElement)) {
      return;
    }

    const form = trigger.closest("form");
    if (!(form instanceof HTMLFormElement)) {
      return;
    }

    const message = trigger.dataset.confirm?.trim();
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

  // Keyboard submission (Enter) does not always produce a click on the submit
  // button, so confirm again for forms that were not approved by a click.
  document.addEventListener("submit", (event) => {
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
  }, true);
})();
