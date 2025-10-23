document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  const username = document.getElementById('login').value;
  const password = document.getElementById('senha').value;

  const body = new URLSearchParams();
  body.append('username', username);
  body.append('password', password);

  try {
    const resp = await fetch('http://127.0.0.1:8000/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body
    });

    const data = await resp.json();

    if (!resp.ok) {
      alert('Falha no login: ' + (data.detail || resp.statusText));
      return;
    }

    // Salva o token JWT localmente
    localStorage.setItem('token', data.access_token);

    alert('Login bem-sucedido!');
    window.location.href = 'dashboard.html';
  } catch (err) {
    console.error(err);
    alert('Erro ao conectar com o servidor');
  }
});