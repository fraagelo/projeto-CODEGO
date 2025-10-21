document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault(); // evita submit padrão

  const username = document.getElementById('login').value;
  const password = document.getElementById('senha').value;

  // cria body application/x-www-form-urlencoded
  const body = new URLSearchParams();
  body.append('username', username);
  body.append('password', password);

  try {
    const resp = await fetch('http://127.0.0.1:8000/login/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body.toString()
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: 'Erro' }));
      alert('Falha no login: ' + (err.detail || resp.statusText));
      return;
    }

    const data = await resp.json();
    // Exemplo: redirecionar após login bem-sucedido
    // (mude para a rota que quiser)
    window.location.href = '/dashboard.html';
  } catch (error) {
    console.error(error);
    alert('Erro ao conectar com o servidor');
  }
});