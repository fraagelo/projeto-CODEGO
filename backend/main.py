from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
# Importações de SQLAlchemy e ORM
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.sql import func
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer
import time
from sqlalchemy.exc import OperationalError
from dotenv import load_dotenv
import os

# --- Carregar Variáveis de Ambiente ---
load_dotenv() 

# --- Configuração de Segurança ---
# Use uma chave forte e consistente. O valor de fallback é só para desenvolvimento.
SECRET_KEY = os.getenv("SECRET_KEY", "CHAVE_SECRETA_DE_FALLBACK_MUITO_SECRETA") 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# DEBUG CRUCIAL: Imprime a chave secreta sendo utilizada para conferência
print("-" * 50)
print(f"INFO DE CHAVE SECRETA: Usando chave (início): {SECRET_KEY[:10]}...")
if SECRET_KEY == "CHAVE_SECRETA_DE_FALLBACK_MUITO_SECRETA":
    print("ALERTA: Usando a chave de fallback padrão! Não use isso em produção.")
print("-" * 50)


# --- Configuração do Banco de Dados ---
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST") 
DB_NAME = os.getenv("DB_NAME")

# Definindo a URL do banco de dados (ajuste se necessário)
if not all([DB_USER, DB_PASSWORD, DB_HOST, DB_NAME]):
    print("Aviso: Variáveis de ambiente do banco de dados não configuradas. Usando DB local padrão.")
    SQLALCHEMY_DATABASE_URL = "mysql+mysqlconnector://root:senha@localhost:3306/meubanco"
else:
    # Atenção: Se estiver usando Docker, o HOST do DB deve ser o nome do serviço (ex: 'db')
    # no seu docker-compose.yml, não 'localhost'.
    SQLALCHEMY_DATABASE_URL = f"mysql+mysqlconnector://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:3306/{DB_NAME}"


engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ----------------------------------------------------------------------
# MODELOS SQLAlchemy (Schema Completo)
# ----------------------------------------------------------------------

# Tabela 1: Usuário (Membros da Equipe)
class Usuario(Base):
    __tablename__ = "usuario"
    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String(150), nullable=False)
    email = Column(String(150), unique=True, index=True, nullable=False)
    senha_hash = Column(String(255), nullable=False)
    login = Column(String(100), unique=True, nullable=False)
    departamento = Column(String(100), nullable=False)
    
    # Relacionamentos (ORM)
    registros = relationship("Registro", back_populates="usuario_criador")

# Tabela 2: Empresa (Clientes ou Parceiros)
class Empresa(Base):
    __tablename__ = "empresa"
    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String(255), nullable=False, index=True)
    cnpj = Column(String(18), unique=True, index=True, nullable=False)
    telefone = Column(String(20))
    email = Column(String(150))
    endereco = Column(String(255))
    
    # Relacionamentos
    contatos = relationship("Contato", back_populates="empresa")

# Tabela 3: Contato (Pessoa dentro da Empresa)
class Contato(Base):
    __tablename__ = "contato"
    id = Column(Integer, primary_key=True, index=True)
    empresa_id = Column(Integer, ForeignKey("empresa.id", ondelete="CASCADE"), nullable=False, index=True)
    nome = Column(String(150), nullable=False)
    cargo = Column(String(100))
    telefone = Column(String(20))
    email = Column(String(150), index=True)
    
    # Relacionamentos
    empresa = relationship("Empresa", back_populates="contatos")
    registros = relationship("Registro", back_populates="contato_associado")

# Tabela 4: Registro (Interações com Contatos)
class Registro(Base):
    __tablename__ = "registro"
    id = Column(Integer, primary_key=True, index=True)
    
    # Chaves Estrangeiras
    usuario_id = Column(Integer, ForeignKey("usuario.id"), nullable=False, index=True)
    contato_id = Column(Integer, ForeignKey("contato.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Dados do Registro
    tipo = Column(String(50), nullable=False)  # Ex: 'Ligação', 'Email', 'Reunião'
    descricao = Column(Text, nullable=False)
    
    # Timestamps
    data_registro = Column(DateTime, server_default=func.now(), index=True)
    data_atualizacao = Column(DateTime, onupdate=func.now())
    
    # Relacionamentos
    usuario_criador = relationship("Usuario", back_populates="registros")
    contato_associado = relationship("Contato", back_populates="registros")


# ----------------------------------------------------------------------
# FUNÇÕES DE AUTENTICAÇÃO E DEPENDÊNCIAS
# ----------------------------------------------------------------------

def criar_token_acesso(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    # Codifica o token usando a SECRET_KEY
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")

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

def verificar_token(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Função para verificar a validade do token JWT.
    
    Inclui logs detalhados para falhas comuns (Chave Secreta Incorreta/Inconsistente).
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não foi possível validar as credenciais (Token inválido, expirado ou formato incorreto).",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if not token:
        raise credentials_exception

    try:
        # Tenta decodificar o token usando a SECRET_KEY carregada
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        login: str = payload.get("sub")
        if login is None:
            print("LOG DEBUG: Token decodificado, mas 'sub' (login) está faltando.")
            raise credentials_exception
            
    except JWTError as e:
        # Se a decodificação falhar, registra a falha com detalhes
        print(f"LOG ERRO DE AUTENTICAÇÃO: Falha ao decodificar JWT. Erro: {e}. Token recebido: {token[:10]}...")
        if "Signature has expired" in str(e):
             print("LOG ERRO: Token expirado! O token foi gerado há mais de 30 minutos.")
        elif "Signature verification failed" in str(e):
             print("LOG ERRO: Falha na verificação de assinatura. Chave Secreta Incorreta/Inconsistente!")
             print(f"Chave usada para decodificar: {SECRET_KEY[:10]}...")
        raise credentials_exception
    
    # Busca o usuário no banco de dados
    usuario = db.query(Usuario).filter(Usuario.login == login).first()
    if usuario is None:
        print(f"LOG DEBUG: Usuário com login '{login}' não encontrado no DB, mas token é válido.")
        raise credentials_exception
        
    return usuario


# ----------------------------------------------------------------------
# INICIALIZAÇÃO E ROTAS
# ----------------------------------------------------------------------

MAX_RETRIES = 10
RETRY_DELAY = 5

def wait_for_db_and_create_tables():
    """Tenta conectar ao DB."""
    print("Tentando conectar ao banco de dados...")
    for i in range(MAX_RETRIES):
        try:
            print("Conexão com o DB bem-sucedida!")
            return
        except OperationalError as e:
            if i < MAX_RETRIES - 1:
                print(f"Tentativa {i+1}/{MAX_RETRIES} falhou. Aguardando {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY)
            else:
                print("Todas as tentativas falharam. Erro fatal.")
                raise e
        except Exception as e:
                print(f"Erro inesperado durante a inicialização do DB: {e}")
                raise e

# Descomente esta linha se ainda não tiver certeza se o DB está funcionando:
# wait_for_db_and_create_tables()

class UsuarioCreate(BaseModel):
    nome: str
    email: EmailStr
    senha: str
    login: str
    departamento: str

app = FastAPI()

# Definições de CORS
origins = ["*", "http://127.0.0.1", "http://localhost", "http://127.0.0.1:5500", "http://localhost:5500"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    
    acess_token = criar_token_acesso(data={"sub": usuario.login}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    
    print(f"LOG INFO: Token gerado com sucesso para o usuário '{usuario.login}'.")
    return {"access_token": acess_token, "token_type": "bearer"}


@app.get("/rota-protegida")
def rota_protegida(usuario: Usuario = Depends(verificar_token)):
    # Retorna uma mensagem confirmando que o usuário foi autenticado
    return {"mensagem": f"Olá, {usuario.nome} do departamento de {usuario.departamento}. Seu acesso ao Dashboard é total."}

@app.get("/health") 
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute("SELECT 1")
        return {"status": "ok", "database": "connected"}
    except Exception:
        return {"status": "error", "database": "disconnected"}