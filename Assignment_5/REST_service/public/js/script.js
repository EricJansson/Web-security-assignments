if (document.getElementById('register'))
  document.getElementById('register').addEventListener('click', function () { registerUser(this); });

function registerUser(button) {
  button.blur();

  const username = $('#username').val();
  const payload = { username };

  $.post({
    url: 'register',
    data: JSON.stringify(payload),
    contentType: 'application/json',
    success: res => {
      if (!res.success) {
        console.log(res.reason || 'Registration failed');
        return;
      }
      $('#token').text(res.token);
    },
    error: xhr => {
      let message;
      if (xhr.responseJSON && xhr.responseJSON.reason) {
        message = xhr.responseJSON.reason;
      } else {
        message = 'Request failed';
      }
      console.log(message);
      $('#token').text(message);
    }
  });
}
