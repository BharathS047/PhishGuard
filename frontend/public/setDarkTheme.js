// Script to force dark theme
(function() {
  localStorage.setItem('theme', 'dark');
  document.documentElement.setAttribute('data-theme', 'dark');
  console.log('Theme set to dark mode');
})(); 