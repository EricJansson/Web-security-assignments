
if (document.getElementById('signin'))
  document.getElementById('signin').addEventListener('click', function () { signin(this); });

if (document.getElementById('signup')) 
  document.getElementById('signup').addEventListener('click', function () { signup(this); });

if (document.getElementById('signout')) 
  document.getElementById('signout').addEventListener('click', function () { signout(this); });

function signup(button) {

  button.blur();

  let username = $('#signupusername').val();
  let password = $('#signuppassword').val();
  let credentials = { username: username, password: password };

  $.post(
    {
      url: 'signup',
      data: JSON.stringify(credentials),
      contentType: 'application/json',
      success: res => {

        if (!res.success) {

          switch (res.reason) {
            case 'username':
              $('#signupusername').addClass('is-invalid');
              $('#signuppassword').removeClass('is-invalid');
              break;

            case 'password':
              $('#signupusername').removeClass('is-invalid');
              $('#signuppassword').addClass('is-invalid');
              break;
          }

        } else {
          location.reload();
        }

      }
    }
  );

}


function signin(button) {

  button.blur();

  let username = $('#username').val();
  let password = $('#password').val();
  let credentials = { username: username, password: password };

  $.post(
    {
      url: 'signin',
      data: JSON.stringify(credentials),
      contentType: 'application/json',
      success: res => {
        if (res.success) {
          location.reload();
        } else {
          $('#username').addClass('is-invalid');
          $('#password').addClass('is-invalid');
        }
      }
    }
  );

}

function signout(button) {

  button.blur();

  $.post('signout', res => {
    console.log(res);
    if (res.success) {
      location.reload();
    }
  }
  );

}