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


SECRET_KEY = "CHAVESECRETAFODA"  # guarde fora do código em produção
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

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

# 3️ Banco de dados
SQLALCHEMY_DATABASE_URL = "mysql+mysqlconnector://root:Joaolopes05%3A@localhost:3306/projeto_codego"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 4️ Modelos
class Usuario(Base):
    __tablename__ = "usuario"
    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String(150), nullable=False)
    email = Column(String(150), unique=True, index=True, nullable=False)
    senha_hash = Column(String(255), nullable=False)
    login = Column(String(100), unique=True, nullable=False)
    departamento = Column(String(100), nullable=False)

Base.metadata.create_all(bind=engine)

# 5️ Modelos Pydantic
class UsuarioCreate(BaseModel):
    nome: str
    email: EmailStr
    senha: str
    login: str
    departamento: str

# 6️ Segurança e utilidades
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
    return {"access_token": acess_token, "token_type": "bearer"}


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
