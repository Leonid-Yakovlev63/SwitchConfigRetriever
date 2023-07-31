function toggleTab(button) {
    const textContent = button.nextElementSibling;
    textContent.style.display = textContent.style.display === 'none' ? 'block' : 'none';
    button.textContent = textContent.style.display === 'none' ? 'Показать текст' : 'Скрыть текст';
}
