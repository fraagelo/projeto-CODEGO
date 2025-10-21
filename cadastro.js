document.getElementById("cadastroForm").addEventListener("submit", async (e) => {
    e.preventDefault();

    const nome = document.getElementById("nome").value.trim();
    const login = document.getElementById("login").value.trim();
    const email = document.getElementById("email").value.trim();
    const senha = document.getElementById("senha").value;
    const confirmar = document.getElementById("confirmar_senha").value;
    const departamento = document.getElementById("departamento").value;

    if (senha !== confirmar) {
        alert("As senhas não coincidem!");
        return;
    }

    const usuario = { nome, email, senha, login, departamento };

    try {
        const resp = await fetch("http://127.0.0.1:8000/cadastro/", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(usuario)
        });

        const data = await resp.json();

        if (!resp.ok) {
            alert("Erro: " + (data.detail || "Não foi possível cadastrar."));
            return;
        }

        alert("Usuário cadastrado com sucesso!");
        window.location.href = "/login.html";
    } catch (error) {
        alert("Erro de conexão com o servidor.");
        console.error(error);
    }
});