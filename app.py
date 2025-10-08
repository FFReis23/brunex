import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'troque_essa_chave_secreta')

# Usa variável de ambiente DATABASE_URL, ou fallback para sqlite local
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///local.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Modelos
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    senha_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_senha(self, senha):
        self.senha_hash = generate_password_hash(senha)

    def checar_senha(self, senha):
        return check_password_hash(self.senha_hash, senha)

class Material(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(50), default='pendente')  # pendente, entregue, coletado
    endereco = db.Column(db.String(120), nullable=True)  # novo campo
    responsavel = db.Column(db.String(100), nullable=True)  # novo campo

# Helpers
def admin_logado():
    return session.get('usuario_id') and session.get('is_admin')

def usuario_logado():
    return session.get('usuario_id')

# Rotas
@app.route('/')
def index():
    if not usuario_logado():
        return redirect(url_for('login'))
    materiais = Material.query.all()
    return render_template('index.html', materiais=materiais, admin=admin_logado())

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = Usuario.query.filter_by(username=request.form['username']).first()
        if usuario and usuario.checar_senha(request.form['senha']):
            session['usuario_id'] = usuario.id
            session['username'] = usuario.username
            session['is_admin'] = usuario.is_admin
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('index'))
        flash('Usuário ou senha incorretos', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Você saiu da sessão.', 'info')
    return redirect(url_for('login'))

@app.route('/add_material', methods=['GET', 'POST'])
def add_material():
    if not admin_logado():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        nome = request.form.get('nome')
        endereco = request.form.get('endereco', '')
        responsavel = request.form.get('responsavel', '')

        material = Material(nome=nome, endereco=endereco, responsavel=responsavel)
        db.session.add(material)
        db.session.commit()
        flash('Material adicionado com sucesso!', 'success')
        return redirect(url_for('index'))

    return render_template('add_material.html')

@app.route('/atualizar_status/<int:id>/<acao>')
def atualizar_status(id, acao):
    if not usuario_logado():
        flash('Faça login para continuar.', 'warning')
        return redirect(url_for('login'))

    material = Material.query.get_or_404(id)
    if acao == 'entregar':
        material.status = 'entregue'
    elif acao == 'coletar':
        material.status = 'coletado'
    else:
        flash('Ação inválida.', 'danger')
        return redirect(url_for('index'))

    db.session.commit()
    flash(f'Material {acao} com sucesso!', 'success')
    return redirect(url_for('index'))

# Criar usuário admin inicial (executar uma vez)
@app.route('/criar_admin')
def criar_admin():
    if Usuario.query.filter_by(username='admin').first():
        return 'Admin já existe.'
    admin = Usuario(username='admin', is_admin=True)
    admin.set_senha('senha123')  # Mude essa senha depois
    db.session.add(admin)
    db.session.commit()
    return 'Admin criado com sucesso.'

@app.route('/criar_tabelas')
def criar_tabelas():
    db.create_all()
    return 'Tabelas criadas com sucesso.'

@app.route('/criar_usuario', methods=['GET', 'POST'])
def criar_usuario():
    if not admin_logado():
        flash('Acesso negado. Apenas admin.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username']
        senha = request.form['senha']

        if Usuario.query.filter_by(username=username).first():
            flash('Usuário já existe.', 'danger')
        else:
            novo_usuario = Usuario(username=username, is_admin=False)
            novo_usuario.set_senha(senha)
            db.session.add(novo_usuario)
            db.session.commit()
            flash('Usuário criado com sucesso!', 'success')
            return redirect(url_for('usuarios'))

    return render_template('criar_usuario.html')

@app.route('/usuarios')
def usuarios():
    if not admin_logado():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('index'))

    usuarios = Usuario.query.all()
    return render_template('usuarios.html', usuarios=usuarios)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
@app.route('/criar_tabelas')
def criar_tabelas():
    db.create_all()
    return 'Tabelas criadas com sucesso.'
