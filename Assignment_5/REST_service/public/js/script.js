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
      $('#out').text(JSON.stringify(res, null, 2));
    },
    error: xhr => {
      let message;
      if (xhr.responseJSON && xhr.responseJSON.reason) {
        message = xhr.responseJSON.reason;
      } else {
        message = 'Request failed';
      }
      console.log(message);
      $('#token').text(message);  // Optional: display the message in the UI
    }
  });
}

// REMOVE BELLOW

if (document.getElementById('doPost'))
  document.getElementById('doPost').addEventListener('click', function () { doPost(this); });

if (document.getElementById('doGet'))
  document.getElementById('doGet').addEventListener('click', function () { doGet(this); });

async function doPost(button) {
  button.blur();

  const username = $('#username').val();
  const token = $('#token').text();
  const bodyText = $('#postBody').val();

  console.log("username:", username);
  console.log("token:", token);
  console.log("bodyText:", bodyText);

  if (!username || !token) { console.log('Register first (username + token).'); return; }

  let body;
  let contentType = 'text/plain';
  try {
    body = JSON.stringify(JSON.parse(bodyText));
    contentType = 'application/json';
  } catch {
    body = bodyText;
  }

  const res = await fetch(`/store/${username}`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': contentType
    },
    body
  });

  const data = await res.json().catch(() => ({ success: false, reason: 'bad json from server' }));
  $('#out').text(JSON.stringify({ status: res.status, data }, null, 2));
}

async function doGet(button) {
  button.blur();
  const username = $('#username').val();
  const token = $('#token').text();

  if (!username || !token) { console.log('Register first (username + token).'); return; }

  const res = await fetch(`/store/${encodeURIComponent(username)}`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${token}` }
  });

  const data = await res.json().catch(() => ({ success: false, reason: 'bad json from server' }));
  $('#out').text(JSON.stringify({ status: res.status, data }, null, 2));
}
