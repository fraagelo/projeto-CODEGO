async function carregarPagina() {
  const token = localStorage.getItem('token');
  if (!token) {
    alert('Você precisa fazer login.');
    window.location.href = 'login.html';
    return;
  }

  const resp = await fetch('http://127.0.0.1:8000/rota-protegida', {
    headers: { 'Authorization': 'Bearer ' + token }
  });

  if (!resp.ok) {
    alert('Acesso não autorizado. Faça login novamente.');
    localStorage.removeItem('token');
    window.location.href = 'login.html';
    return;
  }

  const data = await resp.json();
  document.getElementById('conteudo').textContent = data.mensagem;
}

window.onload = carregarPagina;
