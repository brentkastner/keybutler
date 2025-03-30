/**
 * Key Escrow Service Frontend JavaScript
 * Common functionality for the Zero Trust Key Escrow Service
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
      return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize Bootstrap popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
      return new bootstrap.Popover(popoverTriggerEl);
    });
    
    // // Auto-dismiss alerts after 5 seconds
    // setTimeout(function() {
    //   const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
    //   alerts.forEach(function(alert) {
    //     // Get the Bootstrap alert instance and hide it
    //     const bsAlert = new bootstrap.Alert(alert);
    //     bsAlert.close();
    //   });
    // }, 5000);
    
    // Add current year to footer copyright
    const copyrightYear = document.querySelector('.footer span');
    if (copyrightYear) {
      const currentYear = new Date().getFullYear();
      copyrightYear.textContent = copyrightYear.textContent.replace('{{ now.year }}', currentYear);
    }
    
    // Password strength meter
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
      const strengthMeter = document.createElement('div');
      strengthMeter.className = 'mt-2 password-strength';
      strengthMeter.innerHTML = '<div class="progress" style="height: 5px;"><div class="progress-bar bg-danger" style="width: 0%"></div></div><small class="text-muted mt-1 d-block">Password strength: <span class="strength-text">Very weak</span></small>';
      
      passwordInput.parentNode.appendChild(strengthMeter);
      
      passwordInput.addEventListener('input', function() {
        const password = this.value;
        let strength = 0;
        let progressClass = 'bg-danger';
        let strengthText = 'Very weak';
        
        if (password.length >= 8) strength += 1;
        if (password.length >= 12) strength += 1;
        if (/[A-Z]/.test(password)) strength += 1;
        if (/[0-9]/.test(password)) strength += 1;
        if (/[^A-Za-z0-9]/.test(password)) strength += 1;
        
        const progressBar = strengthMeter.querySelector('.progress-bar');
        const strengthTextElement = strengthMeter.querySelector('.strength-text');
        
        if (strength === 0) {
          progressBar.style.width = '0%';
          progressClass = 'bg-danger';
          strengthText = 'Very weak';
        } else if (strength === 1) {
          progressBar.style.width = '20%';
          progressClass = 'bg-danger';
          strengthText = 'Weak';
        } else if (strength === 2) {
          progressBar.style.width = '40%';
          progressClass = 'bg-warning';
          strengthText = 'Fair';
        } else if (strength === 3) {
          progressBar.style.width = '60%';
          progressClass = 'bg-warning';
          strengthText = 'Good';
        } else if (strength === 4) {
          progressBar.style.width = '80%';
          progressClass = 'bg-success';
          strengthText = 'Strong';
        } else {
          progressBar.style.width = '100%';
          progressClass = 'bg-success';
          strengthText = 'Very strong';
        }
        
        progressBar.className = 'progress-bar ' + progressClass;
        strengthTextElement.textContent = strengthText;
      });
    }
    
    // Countdown timer for TOTP verification
    const totpInput = document.getElementById('totp_code');
    if (totpInput) {
      const timerContainer = document.createElement('div');
      timerContainer.className = 'text-center mt-3';
      timerContainer.innerHTML = 'Code refreshes in <span class="totp-timer badge bg-secondary">30</span> seconds';
      
      totpInput.parentNode.appendChild(timerContainer);
      
      const timerElement = timerContainer.querySelector('.totp-timer');
      
      // Update the timer every second
      function updateTimer() {
        const seconds = Math.floor(30 - (Date.now() / 1000) % 30);
        timerElement.textContent = seconds;
        
        // Change color when close to expiration
        if (seconds <= 5) {
          timerElement.className = 'totp-timer badge bg-danger';
        } else if (seconds <= 10) {
          timerElement.className = 'totp-timer badge bg-warning';
        } else {
          timerElement.className = 'totp-timer badge bg-secondary';
        }
      }
      
      // Initial call and set interval
      updateTimer();
      setInterval(updateTimer, 1000);
    }
  });