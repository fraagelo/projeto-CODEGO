from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer
import time
from sqlalchemy.exc import OperationalError

# --- Configurações de Segurança e Constantes ---
SECRET_KEY = "CHAVESECRETAFODA"  # guarde fora do código em produção
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Removemos a constante BCRYPT_MAX_LENGTH_BYTES pois o SHA256 não tem essa limitação.

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def criar_token_acesso(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# 1️ Cria o app
app = FastAPI()

# 2️ Configura CORS

origins = [
    "*",                        # NOVO: Permite qualquer origem. Essencial para ambientes de teste.
    "http://127.0.0.1",           # NOVO: Endereço IP sem porta
    "http://localhost",           # NOVO: Nome do host sem porta
    "http://127.0.0.1:5500",    # Já existia
    "http://localhost:5500",    # Já existia
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # em produção, especifique a origem
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3️ Banco de dados
import os
# As credenciais agora vêm das variáveis de ambiente definidas no docker-compose.yml
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
# IMPORTANTE: No Docker, o host é o nome do serviço (db) e não localhost
DB_HOST = os.getenv("DB_HOST") 
DB_NAME = os.getenv("DB_NAME")

# Constrói a URL usando as variáveis de ambiente
SQLALCHEMY_DATABASE_URL = f"mysql+mysqlconnector://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:3306/{DB_NAME}"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 4️ Modelos
class Usuario(Base):
    __tablename__ = "usuario"
    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String(150), nullable=False)
    email = Column(String(150), unique=True, index=True, nullable=False)
    # 255 é suficiente para o hash sha256_crypt
    senha_hash = Column(String(255), nullable=False)
    login = Column(String(100), unique=True, nullable=False)
    departamento = Column(String(100), nullable=False)

MAX_RETRIES = 10
RETRY_DELAY = 5  # segundos

def wait_for_db_and_create_tables():
    """Tenta conectar ao DB e criar as tabelas com retentativas."""
    print("Tentando conectar ao banco de dados...")
    for i in range(MAX_RETRIES):
        try:
            # Tenta criar todas as tabelas. Isso força uma conexão imediata.
            Base.metadata.create_all(bind=engine)
            print("Conexão com o DB bem-sucedida e tabelas criadas!")
            return
        except OperationalError as e:
            # OperationalError é esperado se o DB ainda não estiver escutando
            if i < MAX_RETRIES - 1:
                print(f"Tentativa {i+1}/{MAX_RETRIES} falhou. Erro: {e.__class__.__name__}. Aguardando {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY)
            else:
                print("Todas as tentativas falharam. Erro fatal.")
                # Se todas as tentativas falharem, levanta o erro original para o Uvicorn falhar
                raise e
        except Exception as e:
                # Captura outros erros inesperados na inicialização
                print(f"Erro inesperado durante a inicialização do DB: {e}")
                raise e

# Chamada da função para garantir a inicialização antes que o Uvicorn inicie
wait_for_db_and_create_tables()

# 5️ Modelos Pydantic
class UsuarioCreate(BaseModel):
    nome: str
    email: EmailStr
    senha: str
    login: str
    departamento: str

class EmailData(BaseModel):
    email: EmailStr

# 6️ Segurança e utilidades
# MUDANÇA: Alterado de "bcrypt" para "sha256_crypt" para evitar o erro de compatibilidade.
pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")

def hash_senha(senha: str):
    """
    Cria o hash da senha usando sha256_crypt. Não é mais necessário truncar a senha.
    """
    return pwd_context.hash(senha)

def verificar_senha(senha: str, senha_hash: str):
    """
    Verifica a senha usando sha256_crypt.
    """
    return pwd_context.verify(senha, senha_hash)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verificar_token(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não foi possível validar as credenciais",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        login: str = payload.get("sub")
        if login is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    usuario = db.query(Usuario).filter(Usuario.login == login).first()
    if usuario is None:
        raise credentials_exception
    return usuario

# 7️ Rotas
@app.post("/cadastro/")
def cadastro(usuario: UsuarioCreate, db: Session = Depends(get_db)):
    existe_email = db.query(Usuario).filter(Usuario.email == usuario.email).first()
    existe_login = db.query(Usuario).filter(Usuario.login == usuario.login).first()

    if existe_email:
        raise HTTPException(status_code=400, detail="Email já cadastrado")
    if existe_login:
        raise HTTPException(status_code=400, detail="Login já em uso")

    # Usando sha256_crypt
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
    
    # Usando sha256_crypt
    if not usuario or not verificar_senha(form_data.password, usuario.senha_hash):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    
    acess_token = criar_token_acesso(data={"sub": usuario.login}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": acess_token, "token_type": "bearer"}

@app.post("/esqueci-senha")
def forgot_password(data: EmailData, db: Session = Depends(get_db)):
    # ... lógica de busca ...
    
    if usuario:
        # LÓGICA REAL: Gerar token de redefinição e enviar email
        print(f"Simulando envio de redefinição para: {usuario.email}")
    
    # Retorna sucesso sempre para evitar enumeração de usuários
    return {"msg": "Se o email estiver cadastrado, um link de redefinição foi enviado."}

@app.get("/rota-protegida")
def rota_protegida(usuario: Usuario = Depends(verificar_token)):
    return {"mensagem": f"Olá, {usuario.nome}. Você está autenticado."}


@app.get("/health") # ROTA HEALTH CHECK
def health_check(db: Session = Depends(get_db)):
    # Verifica se a conexão com o banco está ok
    try:
        db.execute("SELECT 1")
        return {"status": "ok", "database": "connected"}
    except Exception:
        return {"status": "error", "database": "disconnected"}