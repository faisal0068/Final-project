document.addEventListener('DOMContentLoaded', () => {
  // Create theme toggle button
  const toggleButton = document.createElement('button');
  toggleButton.classList.add('theme-toggle');
  toggleButton.innerHTML = '<i class="fas fa-moon"></i>';  // Default icon (Dark mode)

  // Append button to the body
  document.body.appendChild(toggleButton);

  // Check and apply saved theme from localStorage
  if (localStorage.getItem('theme') === 'dark') {
    document.body.classList.add('dark-mode');
    toggleButton.innerHTML = '<i class="fas fa-sun"></i>'; // Change icon to Sun for light mode
  }

  // Toggle dark mode on button click
  toggleButton.addEventListener('click', () => {
    document.body.classList.toggle('dark-mode');
    
    // Save the current theme in localStorage
    if (document.body.classList.contains('dark-mode')) {
      localStorage.setItem('theme', 'dark');
      toggleButton.innerHTML = '<i class="fas fa-sun"></i>'; // Sun icon for light mode
    } else {
      localStorage.setItem('theme', 'light');
      toggleButton.innerHTML = '<i class="fas fa-moon"></i>'; // Moon icon for dark mode
    }
  });

  // Optional: Make sure the button has a proper aria-label for accessibility
  toggleButton.setAttribute('aria-label', 'Toggle Dark Mode');
});
