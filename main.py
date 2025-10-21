from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext

# 1️⃣ Cria o app
app = FastAPI()

# 2️⃣ Configura CORS

origins = [
    "http://127.0.0.1:5500",  # Live Server (VSCode)
    "http://localhost:5500",  # Live Server alternativa
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # em produção, especifique a origem
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3️⃣ Banco de dados
SQLALCHEMY_DATABASE_URL = "mysql+mysqlconnector://root:Joaolopes05:@localhost:3306/projeto_codego"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 4️⃣ Modelos
class Usuario(Base):
    __tablename__ = "usuario"
    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String(150), nullable=False)
    email = Column(String(150), unique=True, index=True, nullable=False)
    senha_hash = Column(String(255), nullable=False)
    login = Column(String(100), unique=True, nullable=False)
    departamento = Column(String(100), nullable=False)

Base.metadata.create_all(bind=engine)

# 5️⃣ Modelos Pydantic
class UsuarioCreate(BaseModel):
    nome: str
    email: EmailStr
    senha: str
    login: str
    departamento: str

# 6️⃣ Segurança e utilidades
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_senha(senha: str):
    return pwd_context.hash(senha)

def verificar_senha(senha: str, senha_hash: str):
    return pwd_context.verify(senha, senha_hash)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 7️⃣ Rotas
@app.post("/cadastro/")
def cadastro(usuario: UsuarioCreate, db: Session = Depends(get_db)):
    existe_email = db.query(Usuario).filter(Usuario.email == usuario.email).first()
    existe_login = db.query(Usuario).filter(Usuario.login == usuario.login).first()

    if existe_email:
        raise HTTPException(status_code=400, detail="Email já cadastrado")
    if existe_login:
        raise HTTPException(status_code=400, detail="Login já em uso")

    senha_hash = hash_senha(usuario.senha)
    novo_usuario = Usuario(
        nome=usuario.nome,
        email=usuario.email,
        senha_hash=senha_hash,
        login=usuario.login,
        departamento=usuario.departamento
    )

    db.add(novo_usuario)
    db.commit()
    db.refresh(novo_usuario)
    return {"msg": "Usuário criado com sucesso", "usuario_id": novo_usuario.id}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.login == form_data.username).first()
    if not usuario or not verificar_senha(form_data.password, usuario.senha_hash):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    return {"mensagem": "Login bem-sucedido", "usuario": usuario.login}

