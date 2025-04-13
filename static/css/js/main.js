// Dark mode toggle
document.addEventListener('DOMContentLoaded', () => {
    const toggleButton = document.createElement('button');
    toggleButton.innerText = '🌙';
    toggleButton.classList.add('btn', 'btn-outline-secondary');
    toggleButton.style.position = 'fixed';
    toggleButton.style.bottom = '20px';
    toggleButton.style.right = '20px';
    toggleButton.addEventListener('click', () => {
      document.body.classList.toggle('dark-mode');
    });
    document.body.appendChild(toggleButton);
  });
  