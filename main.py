from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext

# Configurações do banco MySQL
SQLALCHEMY_DATABASE_URL = "mysql+mysqlconnector://usuario:senha@endereco_banco/nome_banco"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Modelo SQLAlchemy para usuário
class Usuario(Base):
    __tablename__ = "usuario"
    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String(150), nullable=False)
    email = Column(String(150), unique=True, index=True, nullable=False)
    senha_hash = Column(String(255), nullable=False)

Base.metadata.create_all(bind=engine)

# Pydantic para dados de entrada
class UsuarioCreate(BaseModel):
    nome: str
    email: EmailStr
    senha: str

# Configuração de hash de senha
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

# Dependência para conexão com banco
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Função para criar hash da senha
def hash_senha(senha: str):
    return pwd_context.hash(senha)

# Função para verificar a senha
def verificar_senha(senha: str, senha_hash: str):
    return pwd_context.verify(senha, senha_hash)

# Rota para cadastro
@app.post("/cadastro/")
def cadastro(usuario: UsuarioCreate, db: Session = Depends(get_db)):
    existe = db.query(Usuario).filter(Usuario.email == usuario.email).first()
    if existe:
        raise HTTPException(status_code=400, detail="Email já cadastrado")

    senha_hash = hash_senha(usuario.senha)
    novo_usuario = Usuario(nome=usuario.nome, email=usuario.email, senha_hash=senha_hash)
    db.add(novo_usuario)
    db.commit()
    db.refresh(novo_usuario)
    return {"msg": "Usuário criado com sucesso", "usuario_id": novo_usuario.id}

# Rota para login
@app.post("/login/")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.email == form_data.username).first()
    if not usuario or not verificar_senha(form_data.password, usuario.senha_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou senha inválidos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"msg": f"Bem-vindo {usuario.nome}"}
