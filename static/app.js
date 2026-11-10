document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".flash-close").forEach(button => button.addEventListener("click", () => button.closest(".flash").remove()));
  document.querySelectorAll("form[data-confirm]").forEach(form => form.addEventListener("submit", event => { if (!window.confirm(form.dataset.confirm || "Are you sure?")) event.preventDefault(); }));
  const token = document.querySelector('meta[name="csrf-token"]')?.content;
  if (token) document.querySelectorAll('form[method="post"], form[method="POST"]').forEach(form => {
    if (!form.querySelector('input[name="_csrf_token"]')) { const input=document.createElement('input'); input.type='hidden'; input.name='_csrf_token'; input.value=token; form.appendChild(input); }
  });
});
