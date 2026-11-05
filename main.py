from flask import (Flask, render_template, redirect, request, flash, url_for, session, send_from_directory, send_file,
                   jsonify)
import calendar
import fdb
import pygal
import os
import math
import random
from datetime import date, datetime, timedelta
from fpdf import FPDF
from werkzeug.security import generate_password_hash, check_password_hash
from uuid import uuid4

app = Flask(__name__)
app.config["SECRET_KEY"] = "1234"

host = "localhost"
database = r"C:\Users\Aluno\Desktop\Credmais-FALTASOIMAGEMMM-main\BANCO.FDB"
user = "SYSDBA"
password = "sysdba"


def conectar_banco():
    return fdb.connect(
        host=host,
        database=database,
        user=user,
        password=password
    )


def validar_senha(senha):
    if len(senha) < 8:
        return False

    tem_maiuscula = any(c.isupper() for c in senha)
    tem_minuscula = any(c.islower() for c in senha)
    tem_numero = any(c.isdigit() for c in senha)
    tem_especial = any(not c.isalnum() for c in senha)

    return tem_maiuscula and tem_minuscula and tem_numero and tem_especial


# ADMINISTRADOR
TIPO_ADMIN = 2


@app.context_processor
def dados_do_header():
    try:
        eh_admin = int(session.get("usuario_tipo", 0)) == TIPO_ADMIN
    except (TypeError, ValueError):
        eh_admin = False
    return {"eh_admin": eh_admin}


# ============================================================
# INÍCIO
# ============================================================

@app.route("/")
def inicio():
    return render_template("index.html")


@app.route("/logo")
def logo():
    return send_from_directory(
        os.path.join(app.root_path, "static", "uploads"),
        "logo.png"
    )


@app.route("/fundo")
def fundo():
    return send_from_directory(
        os.path.join(app.root_path, "static", "uploads"),
        "fundo.png"
    )


# ============================================================
# CADASTRO
# ============================================================

@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")
        confirmar_senha = request.form.get("confirmar_senha", "")

        if not nome or not email or not senha or not confirmar_senha:
            flash("Preencha todos os campos.")
            return render_template("cadastro_usuario.html")

        if not any(c.isalpha() for c in nome):
            flash("O nome precisa ter pelo menos uma letra.")
            return render_template("cadastro_usuario.html")

        if not validar_senha(senha):
            flash(
                "A senha deve ter no mínimo 8 caracteres, "
                "uma letra maiúscula, uma letra minúscula, "
                "um número e um caractere especial."
            )
            return render_template("cadastro_usuario.html")

        if senha != confirmar_senha:
            flash("As senhas não são iguais.")
            return render_template("cadastro_usuario.html")

        conexao = None
        cursor = None

        try:
            conexao = conectar_banco()
            cursor = conexao.cursor()

            cursor.execute(
                "SELECT ID_USUARIO FROM USUARIO WHERE EMAIL = ?",
                (email,)
            )

            if cursor.fetchone():
                flash("Este e-mail já está cadastrado.")
                return render_template("cadastro_usuario.html")

            senha_criptografada = generate_password_hash(senha)

            cursor.execute(
                """
                INSERT INTO USUARIO
                (
                    NOME, EMAIL, SENHA, TIPO,
                    ATIVO, TENTATIVAS_LOGIN, BLOQUEADO
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (nome, email, senha_criptografada, 1, True, 0, False)
            )

            cursor.execute(
                "SELECT ID_USUARIO FROM USUARIO WHERE EMAIL = ?",
                (email,)
            )

            usuario = cursor.fetchone()

            if not usuario:
                raise Exception(
                    "Usuário não foi encontrado após o cadastro."
                )

            id_usuario = usuario[0]

            cursor.execute(
                """
                INSERT INTO HISTORICO_SENHA
                    (SENHA, ID_USUARIO, DATA_ALTERACAO)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                """,
                (senha_criptografada, id_usuario)
            )

            conexao.commit()

            flash("Cadastro realizado com sucesso!", "sucesso")
            return redirect(url_for("login"))

        except Exception:
            if conexao:
                conexao.rollback()

            app.logger.exception("Erro ao salvar cadastro.")
            flash("Erro ao salvar o cadastro.")
            return render_template("cadastro_usuario.html")

        finally:
            if cursor:
                cursor.close()
            if conexao:
                conexao.close()

    return render_template("cadastro_usuario.html")


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")

        if not email or not senha:
            flash("Preencha o e-mail e a senha.")
            return render_template("login.html")

        conexao = None
        cursor = None

        try:
            conexao = conectar_banco()
            cursor = conexao.cursor()

            cursor.execute(
                """
                SELECT
                    ID_USUARIO, NOME, EMAIL, SENHA, TIPO,
                    ATIVO, TENTATIVAS_LOGIN, BLOQUEADO, FOTO_PERFIL
                FROM USUARIO
                WHERE EMAIL = ?
                """,
                (email,)
            )

            usuario = cursor.fetchone()

            if not usuario:
                flash("E-mail ou senha incorretos.")
                return render_template("login.html")

            id_usuario = usuario[0]
            nome_usuario = usuario[1]
            email_usuario = usuario[2]
            senha_banco = usuario[3]
            tipo_usuario = usuario[4]
            ativo = usuario[5]
            tentativas_login = int(usuario[6] or 0)
            bloqueado = usuario[7]
            foto_perfil = usuario[8] or ""

            if ativo is False or ativo == 0:
                flash("Sua conta está inativa. Não é possível realizar o login.")
                return render_template("login.html")

            if bloqueado is True or bloqueado == 1:
                flash("Sua conta está bloqueada por excesso de tentativas.")
                return render_template("login.html")

            if not senha_banco:
                flash("Este usuário não possui uma senha cadastrada.")
                return render_template("login.html")

            if not check_password_hash(senha_banco, senha):
                tentativas_login += 1

                if tentativas_login >= 3:
                    cursor.execute(
                        """
                        UPDATE USUARIO
                        SET TENTATIVAS_LOGIN = ?, BLOQUEADO = ?
                        WHERE ID_USUARIO = ?
                        """,
                        (tentativas_login, True, id_usuario)
                    )
                    conexao.commit()

                    flash(
                        "Você atingiu o limite de 3 tentativas. "
                        "Sua conta foi bloqueada."
                    )
                    return render_template("login.html")

                cursor.execute(
                    """
                    UPDATE USUARIO
                    SET TENTATIVAS_LOGIN = ?
                    WHERE ID_USUARIO = ?
                    """,
                    (tentativas_login, id_usuario)
                )
                conexao.commit()

                restantes = 3 - tentativas_login

                if restantes == 1:
                    flash(
                        "E-mail ou senha incorretos. Você tem "
                        "apenas 1 tentativa restante."
                    )
                else:
                    flash(
                        f"E-mail ou senha incorretos. "
                        f"Você ainda possui {restantes} tentativas."
                    )

                return render_template("login.html")

            cursor.execute(
                """
                UPDATE USUARIO
                SET TENTATIVAS_LOGIN = ?, BLOQUEADO = ?
                WHERE ID_USUARIO = ?
                """,
                (0, False, id_usuario)
            )
            conexao.commit()

            session.clear()
            session["usuario_id"] = id_usuario
            session["usuario_nome"] = nome_usuario
            session["usuario_email"] = email_usuario
            session["usuario_tipo"] = tipo_usuario
            session["usuario_foto"] = foto_perfil

            return redirect(url_for("dashboard"))

        except Exception:
            app.logger.exception("Erro no login.")
            flash("Erro ao realizar o login.")
            return render_template("login.html")

        finally:
            if cursor:
                cursor.close()
            if conexao:
                conexao.close()

    return render_template("login.html")


@app.route("/sucesso")
def sucesso():
    if "usuario_id" not in session:
        return redirect(url_for("inicio"))

    return redirect(url_for("dashboard"))


@app.route("/sistema")
def sistema():
    if "usuario_id" not in session:
        return redirect(url_for("inicio"))

    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("inicio"))


@app.route("/sair")
def sair():
    caminho = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(caminho, "sair.png")


# ============================================================
# PERFIL
# ============================================================

def buscar_usuario(id_usuario):
    conexao = conectar_banco()

    try:
        cursor = conexao.cursor()
        try:
            cursor.execute(
                """
                SELECT ID_USUARIO, NOME, EMAIL, SENHA, FOTO_PERFIL
                FROM USUARIO
                WHERE ID_USUARIO = ?
                """,
                (id_usuario,)
            )
            return cursor.fetchone()
        finally:
            cursor.close()
    finally:
        conexao.close()


def email_ja_existe(email, id_usuario):
    conexao = conectar_banco()

    try:
        cursor = conexao.cursor()
        try:
            cursor.execute(
                """
                SELECT ID_USUARIO
                FROM USUARIO
                WHERE EMAIL = ? AND ID_USUARIO <> ?
                """,
                (email, id_usuario)
            )
            return cursor.fetchone() is not None
        finally:
            cursor.close()
    finally:
        conexao.close()


def buscar_ultimas_senhas(id_usuario):
    conexao = conectar_banco()

    try:
        cursor = conexao.cursor()
        try:
            cursor.execute(
                """
                SELECT FIRST 3 SENHA
                FROM HISTORICO_SENHA
                WHERE ID_USUARIO = ?
                ORDER BY DATA_ALTERACAO DESC, ID_HISTORICO_SENHA DESC
                """,
                (id_usuario,)
            )
            return [registro[0] for registro in cursor.fetchall()]
        finally:
            cursor.close()
    finally:
        conexao.close()


@app.route("/perfil", methods=["GET", "POST"])
def perfil():
    if "usuario_id" not in session:
        flash("Faça login para acessar seu perfil.")
        return redirect(url_for("login"))

    id_usuario = session["usuario_id"]

    if request.method == "GET":
        try:
            usuario = buscar_usuario(id_usuario)

            if usuario is None:
                flash("Usuário não encontrado.", "erro")
                return redirect(url_for("login"))

            return render_template(
                "editar_perfil.html",
                nome=usuario[1] or "",
                email=usuario[2] or "",
                foto_perfil=usuario[4] or ""
            )

        except Exception:
            app.logger.exception("Erro ao consultar perfil.")
            flash("Não foi possível carregar o perfil.", "erro")
            return redirect(url_for("dashboard"))

    nome = request.form.get("nome", "").strip()
    email = request.form.get("email", "").strip().lower()
    senha_atual = request.form.get("senha_atual", "")
    nova_senha = request.form.get("nova_senha", "")

    foto = request.files.get("foto")
    nome_foto = None

    if not any(c.isalpha() for c in nome):
        flash("O nome precisa ter pelo menos uma letra.", "erro")
        return redirect(url_for("perfil"))

    if len(nome) > 100 or len(email) > 100:
        flash("Nome e e-mail devem ter no máximo 100 caracteres.", "erro")
        return redirect(url_for("perfil"))

    try:
        usuario = buscar_usuario(id_usuario)

        if usuario is None:
            flash("Usuário não encontrado.", "erro")
            return redirect(url_for("perfil"))

        hash_atual = usuario[3] or ""

        if nova_senha and not senha_atual:
            flash("Informe sua senha atual para definir uma nova senha.", "erro")
            return redirect(url_for("perfil"))

        if email_ja_existe(email, id_usuario):
            flash("Este e-mail já está cadastrado.", "erro")
            return redirect(url_for("perfil"))

        novo_hash = None

        if nova_senha:
            if not check_password_hash(hash_atual, senha_atual):
                flash("A senha atual está incorreta.", "erro")
                return redirect(url_for("perfil"))

            if not validar_senha(nova_senha):
                flash(
                    "A nova senha precisa ter 8 caracteres ou mais, uma letra maiúscula, uma minúscula, um número e um símbolo.",
                    "erro")
                return redirect(url_for("perfil"))

            senhas_anteriores = buscar_ultimas_senhas(id_usuario)

            if check_password_hash(hash_atual, nova_senha):
                flash("A nova senha deve ser diferente da senha atual.", "erro")
                return redirect(url_for("perfil"))

            for senha_antiga in senhas_anteriores:
                if check_password_hash(senha_antiga, nova_senha):
                    flash("Não é permitido reutilizar as três últimas senhas.", "erro")
                    return redirect(url_for("perfil"))

            novo_hash = generate_password_hash(nova_senha)

        if foto and foto.filename:
            extensao = os.path.splitext(foto.filename)[1].lower()

            if extensao not in (".jpg", ".jpeg", ".png", ".webp"):
                flash("Escolha uma imagem JPG, JPEG, PNG ou WEBP.", "erro")
                return redirect(url_for("perfil"))

            nome_foto = f'perfil_{id_usuario}_{uuid4().hex}{extensao}'
            pasta_uploads = os.path.join(app.root_path, "static", "uploads")
            os.makedirs(pasta_uploads, exist_ok=True)
            caminho_foto = os.path.join(pasta_uploads, nome_foto)
            foto.save(caminho_foto)

        conexao = conectar_banco()

        try:
            cursor = conexao.cursor()

            try:
                if novo_hash is not None:
                    cursor.execute(
                        """
                        INSERT INTO HISTORICO_SENHA
                            (SENHA, ID_USUARIO, DATA_ALTERACAO)
                        VALUES (?, ?, ?)
                        """,
                        (hash_atual, id_usuario, datetime.now())
                    )

                if nome_foto:
                    if novo_hash is not None:
                        cursor.execute(
                            """
                            UPDATE USUARIO
                            SET NOME = ?, EMAIL = ?, SENHA = ?,
                                FOTO_PERFIL = ?
                            WHERE ID_USUARIO = ?
                            """,
                            (nome, email, novo_hash, nome_foto, id_usuario)
                        )
                    else:
                        cursor.execute(
                            """
                            UPDATE USUARIO
                            SET NOME = ?, EMAIL = ?, FOTO_PERFIL = ?
                            WHERE ID_USUARIO = ?
                            """,
                            (nome, email, nome_foto, id_usuario)
                        )
                else:
                    if novo_hash is not None:
                        cursor.execute(
                            """
                            UPDATE USUARIO
                            SET NOME = ?, EMAIL = ?, SENHA = ?
                            WHERE ID_USUARIO = ?
                            """,
                            (nome, email, novo_hash, id_usuario)
                        )
                    else:
                        cursor.execute(
                            """
                            UPDATE USUARIO
                            SET NOME = ?, EMAIL = ?
                            WHERE ID_USUARIO = ?
                            """,
                            (nome, email, id_usuario)
                        )

                conexao.commit()

            except Exception:
                conexao.rollback()
                raise

            finally:
                cursor.close()

        finally:
            conexao.close()

        session["usuario_nome"] = nome
        session["usuario_email"] = email
        if nome_foto:
            session["usuario_foto"] = nome_foto

        flash("Perfil atualizado com sucesso!", "sucesso")
        return redirect(url_for("perfil"))

    except Exception:
        app.logger.exception("Erro ao atualizar o perfil.")
        flash("Não foi possível salvar os dados.", "erro")
        return redirect(url_for("perfil"))


@app.route("/perfil/excluir", methods=["POST"])
def excluir_perfil():
    if "usuario_id" not in session:
        return redirect(url_for("login"))
    id_usuario = session["usuario_id"]
    conexao = conectar_banco()
    cursor = conexao.cursor()
    try:
        cursor.execute("SELECT BLOQUEADO FROM USUARIO WHERE ID_USUARIO = ?", (id_usuario,))
        status_usuario = cursor.fetchone()
        if status_usuario and status_usuario[0]:
            cursor.execute("""
                UPDATE USUARIO
                SET BLOQUEADO = ?, TENTATIVAS_LOGIN = ?
                WHERE ID_USUARIO = ?
            """, (False, 0, id_usuario))
            conexao.commit()
            flash("Perfil desbloqueado com sucesso.", "sucesso")
            return redirect(url_for("gerenciar_usuarios"))

        cursor.execute("SELECT ID_SIMULACAO FROM SIMULACAO WHERE ID_USUARIO = ?", (id_usuario,))
        simulacoes = [x[0] for x in cursor.fetchall()]
        for id_simulacao in simulacoes:
            cursor.execute("SELECT ID_EMPRESTIMO FROM EMPRESTIMO WHERE ID_SIMULACAO = ?", (id_simulacao,))
            for emp in cursor.fetchall():
                cursor.execute("DELETE FROM PARCELA WHERE ID_EMPRESTIMO = ?", (emp[0],))
            cursor.execute("DELETE FROM EMPRESTIMO WHERE ID_SIMULACAO = ?", (id_simulacao,))
        cursor.execute("DELETE FROM SIMULACAO WHERE ID_USUARIO = ?", (id_usuario,))
        cursor.execute("DELETE FROM MOV_FINANCEIRA WHERE ID_USUARIO = ?", (id_usuario,))
        cursor.execute("DELETE FROM HISTORICO_SENHA WHERE ID_USUARIO = ?", (id_usuario,))
        cursor.execute("DELETE FROM USUARIO WHERE ID_USUARIO = ?", (id_usuario,))
        conexao.commit()
        session.clear()
        flash("Perfil excluído com sucesso.", "sucesso")
        return redirect(url_for("inicio"))
    except Exception:
        conexao.rollback()
        app.logger.exception("Erro ao excluir perfil.")
        flash("Não foi possível excluir o perfil.", "erro")
        return redirect(url_for("perfil"))
    finally:
        cursor.close()
        conexao.close()


# ============================================================
# MOVIMENTAÇÕES
# ============================================================

TIPO_RECEITA = 1
TIPO_DESPESA = 0

PERIODOS = {
    "ultimos": "Últimos 3 Meses",
    "proximos": "Próximos 3 Meses",
    "todos": "Todo o Tempo",
}


def conectar():
    return conectar_banco()


def id_usuario_movimentacao():
    return session.get("usuario_id")


def formatar_reais(valor):
    texto = f"{float(valor):,.2f}"
    texto = texto.replace(",", "X")
    texto = texto.replace(".", ",")
    return texto.replace("X", ".")


def datas_do_periodo(periodo):
    hoje = date.today()

    if periodo == "ultimos":
        inicio = hoje - timedelta(days=90)
        fim = hoje
    elif periodo == "proximos":
        inicio = hoje
        fim = hoje + timedelta(days=90)
    else:
        inicio = date(2000, 1, 1)
        fim = date(2100, 1, 1)

    return inicio, fim


def montar_movimentacao(linha):
    if linha[3] == TIPO_RECEITA:
        categoria = "Receita"
        classe = "receita"
        sinal = "+"
    else:
        categoria = "Despesa"
        classe = "despesa"
        sinal = "-"

    classificacao = "Fixa" if linha[5] == 1 else "Variável"
    descricao = linha[2] or ""
    valor = float(linha[4])

    return {
        "id": linha[0],
        "data": linha[1].strftime("%d/%m"),
        "data_completa": linha[1].strftime("%d/%m/%Y"),
        "descricao": descricao,
        "categoria": categoria,
        "classe": classe,
        "sinal": sinal,
        "classificacao": classificacao,
        "valor": valor,
        "valor_texto": formatar_reais(valor)
    }


def buscar_movimentacoes(data_inicio, data_fim):
    con = conectar()

    try:
        cursor = con.cursor()
        try:
            cursor.execute(
                """
                SELECT
                    ID_MOV_FINANCEIRA, DATA_LANCAMENTO, DESCRICAO,
                    TIPO, VALOR, CLASSIFICACAO
                FROM MOV_FINANCEIRA
                WHERE ID_USUARIO = ?
                  AND DATA_LANCAMENTO >= ?
                  AND DATA_LANCAMENTO <= ?
                  AND DESCRICAO NOT LIKE 'Parcela de empréstimo %'
                ORDER BY DATA_LANCAMENTO DESC, ID_MOV_FINANCEIRA DESC
                """,
                (id_usuario_movimentacao(), data_inicio, data_fim)
            )

            return [
                montar_movimentacao(linha)
                for linha in cursor.fetchall()
            ]
        finally:
            cursor.close()
    finally:
        con.close()


def buscar_movimentacao(id_mov):
    con = conectar()

    try:
        cursor = con.cursor()
        try:
            cursor.execute(
                """
                SELECT
                    ID_MOV_FINANCEIRA, DATA_LANCAMENTO, DESCRICAO,
                    TIPO, VALOR, CLASSIFICACAO
                FROM MOV_FINANCEIRA
                WHERE ID_MOV_FINANCEIRA = ? AND ID_USUARIO = ?
                  AND DESCRICAO NOT LIKE 'Parcela de empréstimo %'
                """,
                (id_mov, id_usuario_movimentacao())
            )

            linha = cursor.fetchone()
            return montar_movimentacao(linha) if linha else None
        finally:
            cursor.close()
    finally:
        con.close()


def somar(tipo, data_inicio=date(2000, 1, 1)):
    con = conectar()

    try:
        cursor = con.cursor()
        try:
            cursor.execute(
                """
                SELECT VALOR
                FROM MOV_FINANCEIRA
                WHERE ID_USUARIO = ?
                  AND TIPO = ?
                  AND DATA_LANCAMENTO >= ?
                  AND DESCRICAO NOT LIKE 'Parcela de empréstimo %'
                """,
                (id_usuario_movimentacao(), tipo, data_inicio)
            )

            return sum(float(linha[0]) for linha in cursor.fetchall())
        finally:
            cursor.close()
    finally:
        con.close()


def somar_mes(tipo):
    hoje = date.today()
    inicio = hoje.replace(day=1)

    if hoje.month == 12:
        fim = date(hoje.year + 1, 1, 1)
    else:
        fim = date(hoje.year, hoje.month + 1, 1)

    con = conectar()

    try:
        cursor = con.cursor()
        try:
            cursor.execute(
                """
                SELECT VALOR
                FROM MOV_FINANCEIRA
                WHERE ID_USUARIO = ?
                  AND TIPO = ?
                  AND DATA_LANCAMENTO >= ?
                  AND DATA_LANCAMENTO < ?
                  AND DESCRICAO NOT LIKE 'Parcela de empréstimo %'
                """,
                (id_usuario_movimentacao(), tipo, inicio, fim)
            )

            return sum(float(linha[0]) for linha in cursor.fetchall())
        finally:
            cursor.close()
    finally:
        con.close()


@app.route("/movimentacoes")
def movimentacoes():
    if "usuario_id" not in session:
        flash("Faça login para acessar esta página.", "erro")
        return redirect(url_for("login"))

    periodo = request.args.get("periodo", "ultimos")

    if periodo not in PERIODOS:
        periodo = "ultimos"

    data_inicio, data_fim = datas_do_periodo(periodo)
    dados = buscar_movimentacoes(data_inicio, data_fim)

    saldo = somar(TIPO_RECEITA) - somar(TIPO_DESPESA)

    inicio_30_dias = date.today() - timedelta(days=30)
    receitas = somar(TIPO_RECEITA, inicio_30_dias)
    despesas = somar(TIPO_DESPESA, inicio_30_dias)

    return render_template(
        "movimentacoes.html",
        dados=dados,
        saldo_texto=formatar_reais(saldo),
        receitas_texto=formatar_reais(receitas),
        despesas_texto=formatar_reais(despesas),
        periodo=periodo
    )


@app.route("/nova-movimentacao", methods=["GET", "POST"])
def nova_movimentacao():
    if "usuario_id" not in session:
        flash("Faça login para acessar esta página.", "erro")
        return redirect(url_for("login"))

    if request.method == "POST":
        tipo = request.form.get("tipo", "").strip()
        categoria = request.form.get("categoria", "").strip()
        valor = request.form.get("valor", "").strip()
        classificacao = request.form.get("classificacao", "2")
        meses = request.form.get("meses", "1")

        if not tipo:
            flash("Informe o tipo de movimentação.", "erro")
            return redirect(url_for("nova_movimentacao"))

        if categoria not in ("Receita", "Despesa"):
            flash("Selecione Receita ou Despesa.", "erro")
            return redirect(url_for("nova_movimentacao"))

        try:
            valor_numerico = converter_valor(valor)
        except (ValueError, AttributeError):
            valor_numerico = 0

        if valor_numerico <= 0:
            flash("Insira um valor válido.", "erro")
            return redirect(url_for("nova_movimentacao"))

        if classificacao == "1":
            classificacao_numero = 1

            try:
                quantidade = int(meses)
            except ValueError:
                quantidade = 0

            if quantidade < 1 or quantidade > 120:
                flash("Informe de 1 a 120 meses.", "erro")
                return redirect(url_for("nova_movimentacao"))
        else:
            classificacao_numero = 2
            quantidade = 1

        tipo_numero = (
            TIPO_RECEITA if categoria == "Receita" else TIPO_DESPESA
        )

        con = conectar()

        try:
            cursor = con.cursor()

            try:
                hoje = date.today()

                for i in range(quantidade):
                    total_meses = hoje.month - 1 + i
                    ano = hoje.year + total_meses // 12
                    mes = total_meses % 12 + 1
                    ultimo_dia = calendar.monthrange(ano, mes)[1]
                    dia = min(hoje.day, ultimo_dia)
                    data_mov = date(ano, mes, dia)

                    cursor.execute(
                        """
                        INSERT INTO MOV_FINANCEIRA
                        (
                            TIPO, VALOR, DATA_LANCAMENTO,
                            DESCRICAO, ID_USUARIO, CLASSIFICACAO
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            tipo_numero,
                            valor_numerico,
                            data_mov,
                            tipo,
                            id_usuario_movimentacao(),
                            classificacao_numero
                        )
                    )

                con.commit()

            except Exception:
                con.rollback()
                raise

        finally:
            con.close()

        session["ultima_movimentacao"] = {
            "valor_texto": formatar_reais(valor_numerico),
            "categoria": categoria,
            "descricao": tipo,
            "classe": "receita" if categoria == "Receita" else "despesa"
        }

        return redirect(url_for("movimentacao_registrada"))

    return render_template("nova_movimentacao.html")


@app.route("/movimentacao-registrada")
def movimentacao_registrada():
    dados = session.pop("ultima_movimentacao", None)

    if dados is None:
        return redirect(url_for("movimentacoes"))

    return render_template("movimentacao_registrada.html", dados=dados)


@app.route("/movimentacao/<int:id_mov>")
def visualizar_movimentacao(id_mov):
    mov = buscar_movimentacao(id_mov)

    if "usuario_id" not in session:
        flash("Faça login para acessar esta página.", "erro")
        return redirect(url_for("login"))

    if mov is None:
        flash("Movimentação não encontrada.", "erro")
        return redirect(url_for("movimentacoes"))

    return render_template("visualizar_movimentacao.html", mov=mov)


@app.route("/movimentacao/<int:id_mov>/editar", methods=["GET", "POST"])
def editar_movimentacao(id_mov):
    mov = buscar_movimentacao(id_mov)

    if mov is None:
        flash("Movimentação não encontrada.", "erro")
        return redirect(url_for("movimentacoes"))

    if request.method == "POST":
        descricao = request.form.get("descricao", "").strip()

        if not descricao:
            flash("Informe a descrição da movimentação.", "erro")
            return redirect(url_for("editar_movimentacao", id_mov=id_mov))

        if len(descricao) > 100:
            flash("A descrição pode ter no máximo 100 caracteres.", "erro")
            return redirect(url_for("editar_movimentacao", id_mov=id_mov))

        con = conectar()

        try:
            cursor = con.cursor()
            try:
                cursor.execute(
                    """
                    UPDATE MOV_FINANCEIRA
                    SET DESCRICAO = ?
                    WHERE ID_MOV_FINANCEIRA = ? AND ID_USUARIO = ?
                    """,
                    (descricao, id_mov, id_usuario_movimentacao())
                )
                con.commit()
            except Exception:
                con.rollback()
                raise
        finally:
            con.close()

        flash("Descrição atualizada com sucesso!", "sucesso")
        return redirect(
            url_for("visualizar_movimentacao", id_mov=id_mov)
        )

    return render_template("editar_movimentacao.html", mov=mov)


@app.route("/movimentacao/<int:id_mov>/excluir", methods=["POST"])
def excluir_movimentacao(id_mov):
    mov = buscar_movimentacao(id_mov)

    if mov is None:
        flash("Movimentação não encontrada.", "erro")
        return redirect(url_for("movimentacoes"))

    con = conectar()
    id_usuario = id_usuario_movimentacao()

    try:
        cursor = con.cursor()

        try:
            if mov["classificacao"] == "Fixa":
                tipo_numero = (
                    TIPO_RECEITA
                    if mov["categoria"] == "Receita"
                    else TIPO_DESPESA
                )

                cursor.execute(
                    """
                    SELECT ID_MOV_FINANCEIRA, VALOR
                    FROM MOV_FINANCEIRA
                    WHERE ID_USUARIO = ?
                      AND CLASSIFICACAO = 1
                      AND TIPO = ?
                      AND DESCRICAO = ?
                    """,
                    (id_usuario, tipo_numero, mov["descricao"])
                )

                candidatas = cursor.fetchall()
                quantidade = 0

                for candidata in candidatas:
                    if float(candidata[1]) == mov["valor"]:
                        cursor.execute(
                            """
                            DELETE FROM MOV_FINANCEIRA
                            WHERE ID_MOV_FINANCEIRA = ? AND ID_USUARIO = ?
                            """,
                            (candidata[0], id_usuario)
                        )
                        quantidade += 1

                if quantidade == 1:
                    mensagem = "Movimentação excluída com sucesso!"
                else:
                    mensagem = (
                        f"{quantidade} movimentações fixas iguais "
                        "foram excluídas com sucesso!"
                    )
            else:
                cursor.execute(
                    """
                    DELETE FROM MOV_FINANCEIRA
                    WHERE ID_MOV_FINANCEIRA = ? AND ID_USUARIO = ?
                    """,
                    (id_mov, id_usuario)
                )
                mensagem = "Movimentação excluída com sucesso!"

            con.commit()

        except Exception:
            con.rollback()
            raise

    finally:
        con.close()

    flash(mensagem, "sucesso")
    return redirect(url_for("movimentacoes"))


# ============================================================
# RELATÓRIO PDF
# ============================================================

def texto_pdf(texto):
    texto = str(texto).encode("latin-1", "replace")
    return texto.decode("latin-1")


@app.route("/relatorio", methods=["GET"])
def relatorio():
    periodo = request.args.get("periodo", "ultimos")

    if periodo not in PERIODOS:
        periodo = "ultimos"

    data_inicio, data_fim = datas_do_periodo(periodo)
    movimentacoes_pdf = buscar_movimentacoes(data_inicio, data_fim)

    if not movimentacoes_pdf:
        return jsonify({
            "erro": "Nenhuma movimentação encontrada no período."
        }), 404

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Arial", style="B", size=16)
    pdf.cell(
        190, 10,
        texto_pdf("Relatório de Movimentações - CredMais"),
        ln=True,
        align="C"
    )

    pdf.set_font("Arial", size=10)
    pdf.cell(
        190, 8,
        texto_pdf(
            f"Período: {PERIODOS[periodo]} | "
            f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M')}"
        ),
        ln=True,
        align="C"
    )

    pdf.ln(5)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)

    pdf.set_font("Arial", style="B", size=10)
    pdf.cell(30, 10, "Data", border=1)
    pdf.cell(75, 10, texto_pdf("Descrição"), border=1)
    pdf.cell(35, 10, "Categoria", border=1)
    pdf.cell(50, 10, texto_pdf("Valor (R$)"), border=1, ln=True)

    pdf.set_font("Arial", size=9)
    total_receitas = 0
    total_despesas = 0

    for item in movimentacoes_pdf:
        if item["categoria"] == "Receita":
            total_receitas += item["valor"]
            sinal = "+"
        else:
            total_despesas += item["valor"]
            sinal = "-"

        pdf.cell(30, 10, item["data_completa"], border=1)
        pdf.cell(75, 10, texto_pdf(item["descricao"])[:38], border=1)
        pdf.cell(35, 10, texto_pdf(item["categoria"]), border=1)
        pdf.cell(
            50, 10,
            texto_pdf(f"{sinal} R$ {formatar_reais(item['valor'])}"),
            border=1,
            ln=True
        )

    pdf.ln(10)
    pdf.set_font("Arial", style="B", size=11)
    pdf.cell(
        190, 10,
        f"Total de movimentacoes: {len(movimentacoes_pdf)}",
        ln=True,
        align="C"
    )
    pdf.cell(
        190, 10,
        texto_pdf(f"Receitas: R$ {formatar_reais(total_receitas)}"),
        ln=True,
        align="C"
    )
    pdf.cell(
        190, 10,
        texto_pdf(f"Despesas: R$ {formatar_reais(total_despesas)}"),
        ln=True,
        align="C"
    )
    pdf.cell(
        190, 10,
        texto_pdf(
            f"Saldo do período: R$ "
            f"{formatar_reais(total_receitas - total_despesas)}"
        ),
        ln=True,
        align="C"
    )

    pdf_path = os.path.join(
        app.root_path, "relatorio_movimentacoes.pdf"
    )
    pdf.output(pdf_path)

    return send_file(
        pdf_path,
        as_attachment=True,
        mimetype="application/pdf"
    )


# ============================================================
# TAXAS DE JUROS
# ============================================================

def converter_taxa(linha):
    data_referencia = linha[1]

    if isinstance(data_referencia, datetime):
        data_referencia = data_referencia.date()

    return {
        "id": linha[0],
        "id_taxa_juros": linha[0],
        "data_referencia": data_referencia,
        "ano": data_referencia.year,
        "juros": float(linha[2]),
        "taxa_mensal": float(linha[2])
    }


def buscar_taxas_banco():
    conexao = conectar_banco()

    try:
        cursor = conexao.cursor()

        try:
            cursor.execute(
                """
                SELECT ID_TAXA_JUROS, DATA_REFERENCIA, TAXA_MENSAL
                FROM TAXA_JUROS
                ORDER BY DATA_REFERENCIA DESC, ID_TAXA_JUROS DESC
                """
            )

            return [
                converter_taxa(linha)
                for linha in cursor.fetchall()
            ]

        finally:
            cursor.close()

    finally:
        conexao.close()


def buscar_taxa_por_ano(ano):
    conexao = conectar_banco()

    try:
        cursor = conexao.cursor()

        try:
            cursor.execute(
                """
                SELECT FIRST 1
                    ID_TAXA_JUROS, DATA_REFERENCIA, TAXA_MENSAL
                FROM TAXA_JUROS
                WHERE EXTRACT(YEAR FROM DATA_REFERENCIA) = ?
                ORDER BY ID_TAXA_JUROS DESC
                """,
                (ano,)
            )

            linha = cursor.fetchone()

            if linha is None:
                return None

            return converter_taxa(linha)

        finally:
            cursor.close()

    finally:
        conexao.close()


def buscar_taxa_por_id(id_taxa):
    conexao = conectar_banco()

    try:
        cursor = conexao.cursor()

        try:
            cursor.execute(
                """
                SELECT ID_TAXA_JUROS, DATA_REFERENCIA, TAXA_MENSAL
                FROM TAXA_JUROS
                WHERE ID_TAXA_JUROS = ?
                """,
                (id_taxa,)
            )

            linha = cursor.fetchone()

            if linha is None:
                return None

            return converter_taxa(linha)

        finally:
            cursor.close()

    finally:
        conexao.close()


def validar_dados_taxa(ano_texto, juros_texto):
    try:
        ano = int(ano_texto)
        juros = float(juros_texto.strip().replace(",", "."))

    except (ValueError, TypeError, AttributeError):
        raise ValueError("Informe um ano e uma taxa válidos.")

    if ano < 1900 or ano > 9999:
        raise ValueError("Informe um ano válido.")

    if juros < 0:
        raise ValueError("A taxa de juros não pode ser negativa.")

    return ano, juros


@app.route("/taxas/editar", methods=["GET", "POST"])
def editar_taxa():
    if "usuario_id" not in session:
        flash("Faça login para acessar esta página.", "erro")
        return redirect(url_for("login"))

    if request.method == "POST":
        ano_texto = request.form.get("ano", "").strip()
        juros_texto = request.form.get("juros", "").strip()

        try:
            ano, juros = validar_dados_taxa(ano_texto, juros_texto)
            taxa_existente = buscar_taxa_por_ano(ano)

            if taxa_existente is None:
                flash("Não existe uma taxa cadastrada para esse ano.", "erro")
                return redirect(url_for("editar_taxa"))

            conexao = conectar_banco()

            try:
                cursor = conexao.cursor()
                cursor.execute(
                    """
                    UPDATE TAXA_JUROS
                    SET TAXA_MENSAL = ?
                    WHERE ID_TAXA_JUROS = ?
                    """,
                    (juros, taxa_existente["id"])
                )
                conexao.commit()
                cursor.close()
            finally:
                conexao.close()

            flash("Taxa atualizada com sucesso!", "sucesso")
            return redirect(url_for("editar_taxa", ano=ano))

        except ValueError as erro:
            flash(str(erro), "erro")
            return redirect(url_for("editar_taxa"))

        except Exception:
            app.logger.exception("Erro ao editar taxa.")
            flash("Não foi possível salvar as alterações.", "erro")
            return redirect(url_for("editar_taxa"))

    ano_texto = request.args.get("ano", "").strip()

    try:
        if ano_texto:
            taxa = buscar_taxa_por_ano(int(ano_texto))
        else:
            taxas = buscar_taxas_banco()
            taxa = taxas[0] if taxas else {"ano": "", "juros": ""}

    except ValueError:
        taxa = {"ano": "", "juros": ""}
        flash("O ano informado é inválido.", "erro")

    except Exception:
        app.logger.exception("Erro ao carregar taxa para edição.")
        taxa = {"ano": "", "juros": ""}
        flash("Não foi possível carregar as taxas do banco.", "erro")

    if taxa is None:
        taxa = {"ano": "", "juros": ""}
        flash("Não foi encontrada uma taxa para esse ano.", "erro")

    return render_template("editar_taxas.html", taxa=taxa)


@app.route("/taxas/cadastrar", methods=["GET", "POST"])
def cadastrar_taxa():
    taxa = {"ano": "", "juros": ""}
    if "usuario_id" not in session:
        flash("Faça login para acessar esta página.", "erro")
        return redirect(url_for("login"))

    if request.method == "POST":
        ano_texto = request.form.get("ano", "").strip()
        juros_texto = request.form.get("juros", "").strip()

        taxa = {
            "ano": ano_texto,
            "juros": juros_texto
        }

        try:
            ano, juros = validar_dados_taxa(ano_texto, juros_texto)
            taxa_existente = buscar_taxa_por_ano(ano)

            if taxa_existente is not None:
                flash(f"Já existe uma taxa cadastrada para o ano {ano}.", "erro")
                return render_template("cadastrar_taxas.html", taxa=taxa)

            data_referencia = date(ano, 1, 1)
            conexao = conectar_banco()

            try:
                cursor = conexao.cursor()

                try:
                    cursor.execute(
                        """
                        INSERT INTO TAXA_JUROS
                            (DATA_REFERENCIA, TAXA_MENSAL)
                        VALUES (?, ?)
                        """,
                        (data_referencia, juros)
                    )
                    conexao.commit()
                except Exception:
                    conexao.rollback()
                    raise
                finally:
                    cursor.close()
            finally:
                conexao.close()

            flash("Taxa cadastrada com sucesso!", "sucesso")
            return redirect(url_for("cadastrar_taxa"))

        except ValueError as erro:
            flash(str(erro), "erro")
            return render_template("cadastrar_taxas.html", taxa=taxa)

        except Exception:
            app.logger.exception("Erro ao cadastrar taxa.")
            flash("Não foi possível cadastrar a taxa no banco de dados.", "erro")
            return render_template("cadastrar_taxas.html", taxa=taxa)

    return render_template("cadastrar_taxas.html", taxa=taxa)


@app.route("/taxas")
def listar_taxas():
    try:
        taxas = buscar_taxas_banco()
    except Exception:
        app.logger.exception("Erro ao listar taxas.")
        flash("Não foi possível consultar as taxas no banco.", "erro")
        taxas = []

    return render_template("listar_taxas.html", taxas=taxas)


@app.route("/taxas/administrar")
def administrar_taxas():
    try:
        taxas = buscar_taxas_banco()
    except Exception:
        app.logger.exception("Erro ao carregar administração de taxas.")
        flash("Não foi possível consultar as taxas no banco.", "erro")
        taxas = []

    return render_template("administrar_taxas.html", taxas=taxas)


@app.route("/logo_taxas")
def logo_taxas():
    caminho = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(caminho, "logo_taxas.png")


@app.route("/icone_taxas")
def icone_taxas():
    caminho = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(caminho, "icone_taxas.png")


# ============================================================
# DASHBOARD
# ============================================================

def gerar_grafico_dashboard(id_usuario):
    hoje = date.today()
    primeiro_mes = hoje.year * 12 + hoje.month - 1 - 5
    ano_inicio = primeiro_mes // 12
    mes_inicio = primeiro_mes % 12 + 1
    data_inicio = date(ano_inicio, mes_inicio, 1)

    conexao = conectar_banco()
    cursor = conexao.cursor()
    try:
        cursor.execute("""
            SELECT DATA_LANCAMENTO, TIPO, VALOR
            FROM MOV_FINANCEIRA
            WHERE ID_USUARIO = ? AND DATA_LANCAMENTO >= ? AND DATA_LANCAMENTO <= ?
              AND DESCRICAO NOT LIKE 'Parcela de empréstimo %'
            ORDER BY DATA_LANCAMENTO
        """, (id_usuario, data_inicio, hoje))
        registros = cursor.fetchall()
    finally:
        cursor.close()
        conexao.close()

    meses = []
    for i in range(6):
        total_meses = primeiro_mes + i
        ano = total_meses // 12
        mes = total_meses % 12 + 1
        meses.append({
            "ano": ano, "mes": mes, "nome": f"{mes:02d}/{ano}",
            "receitas": 0.0, "despesas": 0.0
        })

    meses_por_chave = {(item["ano"], item["mes"]): item for item in meses}
    for registro in registros:
        data_mov = registro[0]
        if isinstance(data_mov, datetime):
            data_mov = data_mov.date()
        chave = (data_mov.year, data_mov.month)
        if chave in meses_por_chave:
            valor = float(registro[2] or 0)
            if registro[1] == TIPO_RECEITA:
                meses_por_chave[chave]["receitas"] += valor
            else:
                meses_por_chave[chave]["despesas"] += valor

    grafico = pygal.Bar(
        height=330,
        x_label_rotation=0,
        show_y_guides=True,
        show_x_guides=False,
        show_legend=False,
        style=pygal.style.Style(
            background="white",
            plot_background="white",
            foreground="#59677D",
            foreground_strong="#153779",
            foreground_subtle="#E8EDF5",
            colors=("#1768F9", "#16A879"),
            opacity=0.95,
            opacity_hover=1,
            transition="400ms"
        )
    )
    grafico.title = ""
    grafico.x_labels = [item["nome"] for item in meses]
    grafico.add("Receitas", [round(item["receitas"], 2) for item in meses])
    grafico.add("Despesas", [round(item["despesas"], 2) for item in meses])

    pasta_graficos = os.path.join(app.root_path, "static", "graficos")
    os.makedirs(pasta_graficos, exist_ok=True)
    caminho_svg = os.path.join(pasta_graficos, "grafico_dashboard.svg")
    grafico.render_to_file(caminho_svg)
    return url_for("static", filename="graficos/grafico_dashboard.svg")


@app.route("/dashboard")
def dashboard():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    hoje = date.today()
    data_atual = hoje.strftime("%d/%m/%Y")
    id_usuario = session["usuario_id"]
    parcelas_futuras = []
    comprometimento_anual = 0

    conexao = conectar_banco()
    cursor = conexao.cursor()
    try:
        cursor.execute("""
            SELECT p.VALOR, p.DATA_VENCIMENTO
            FROM PARCELA p
            JOIN EMPRESTIMO e ON p.ID_EMPRESTIMO = e.ID_EMPRESTIMO
            JOIN SIMULACAO s ON e.ID_SIMULACAO = s.ID_SIMULACAO
            WHERE s.ID_USUARIO = ? AND p.STATUS <> 'Pago'
              AND p.DATA_VENCIMENTO >= ?
            ORDER BY p.DATA_VENCIMENTO
        """, (id_usuario, hoje))
        for linha in cursor.fetchall():
            valor = float(linha[0] or 0)
            vencimento = linha[1]
            parcelas_futuras.append({"valor": valor, "data_objeto": vencimento})

        limite_anual = hoje + timedelta(days=365)
        for parcela in parcelas_futuras:
            if parcela["data_objeto"] <= limite_anual:
                comprometimento_anual += parcela["valor"]
    except Exception:
        app.logger.exception("Erro ao carregar parcelas do dashboard.")
    finally:
        cursor.close()
        conexao.close()

    total_parcelas_futuras = sum(p["valor"] for p in parcelas_futuras)
    quantidade_parcelas_futuras = len(parcelas_futuras)

    if parcelas_futuras:
        proxima = parcelas_futuras[0]
        proxima_parcela_valor = formatar_reais(proxima["valor"])
        proxima_parcela_data = proxima["data_objeto"].strftime("%d/%m/%Y")
    else:
        proxima_parcela_valor = "-"
        proxima_parcela_data = "Nenhuma parcela cadastrada"

    renda_anual_estimada = (somar_mes(TIPO_RECEITA) - somar_mes(TIPO_DESPESA)) * 12
    if renda_anual_estimada > 0:
        percentual_comprometimento_anual = formatar_reais(
            (comprometimento_anual / renda_anual_estimada) * 100
        )
    else:
        percentual_comprometimento_anual = "-"

    svg = gerar_grafico_dashboard(id_usuario)

    return render_template(
        "dashboard.html",
        svg=svg,
        data_atual=data_atual,
        renda_mensal_liquida=formatar_reais(somar_mes(TIPO_RECEITA) - somar_mes(TIPO_DESPESA)),
        receita_total=formatar_reais(somar(TIPO_RECEITA)),
        despesa_total=formatar_reais(somar(TIPO_DESPESA)),
        comprometimento_anual=formatar_reais(comprometimento_anual),
        percentual_comprometimento_anual=percentual_comprometimento_anual,
        parcelas_futuras=formatar_reais(total_parcelas_futuras),
        quantidade_parcelas_futuras=quantidade_parcelas_futuras,
        proxima_parcela_valor=proxima_parcela_valor,
        proxima_parcela_data=proxima_parcela_data
    )


@app.route("/logo_dashboard")
def logo_dashboard():
    caminho = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(caminho, "logo_dashboard.png")


@app.route("/dinheiro")
def dinheiro():
    caminho = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(caminho, "dinheiro.png")


@app.route("/check")
def check():
    caminho = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(caminho, "check.png")


@app.route("/quadrado")
def quadrado():
    caminho = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(caminho, "quadrado.png")


@app.route("/calculadora")
def calculadora():
    caminho = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(caminho, "calculadora.png")


@app.route("/escudo")
def escudo():
    caminho = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(caminho, "escudo.png")


@app.route("/predio")
def predio():
    caminho = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(caminho, "predio.png")


# ============================================================
# EMPRÉSTIMOS
# ============================================================

def converter_valor(valor):
    valor = valor.strip().replace("R$", "").replace(" ", "")

    if "," in valor:
        valor = valor.replace(".", "").replace(",", ".")

    return float(valor)


def gerar_parcelas(emprestimo):
    parcelas = []
    data = datetime.strptime(emprestimo["data"], "%d/%m/%Y")

    quantidade = emprestimo["quantidade_parcelas"]
    valor_parcela = emprestimo["valor_parcela"]

    for numero in range(1, quantidade + 1):
        mes_total = data.month + numero
        ano = data.year + (mes_total - 1) // 12
        mes = (mes_total - 1) % 12 + 1

        dia = min(data.day, calendar.monthrange(ano, mes)[1])
        vencimento = datetime(ano, mes, dia)

        parcelas.append({
            "numero": numero,
            "vencimento": vencimento.strftime("%d/%m/%Y"),
            "valor": valor_parcela,
            "valor_formatado": "R$ " + formatar_reais(valor_parcela),
            "status": (
                "Pago"
                if numero <= emprestimo.get("parcelas_pagas", 0)
                else "Pendente"
            )
        })

    return parcelas


def atualizar_parcelas_pendentes(cursor, id_emprestimo, id_usuario, taxa_valor):
    cursor.execute("""
        SELECT s.VALOR_EMPRESTIMO, t.TAXA_MENSAL
        FROM EMPRESTIMO e
        JOIN SIMULACAO s ON e.ID_SIMULACAO = s.ID_SIMULACAO
        JOIN TAXA_JUROS t ON s.ID_TAXA_JUROS = t.ID_TAXA_JUROS
        WHERE e.ID_EMPRESTIMO = ?
    """, (id_emprestimo,))
    linha = cursor.fetchone()
    if not linha:
        return

    taxa_original = float(linha[1] or taxa_valor)
    saldo = float(linha[0] or 0)
    cursor.execute("""
        SELECT NUM_PARCELAS, VALOR, STATUS, TAXA_APLICADA
        FROM PARCELA WHERE ID_EMPRESTIMO = ? ORDER BY NUM_PARCELAS
    """, (id_emprestimo,))
    parcelas = cursor.fetchall()

    for parcela in parcelas:
        if parcela[2] == "Pago":
            taxa_antiga = float(parcela[3]) if parcela[3] is not None else taxa_original
            juros = saldo * (taxa_antiga / 100)
            saldo = max(0, saldo - (float(parcela[1]) - juros))

    pendentes = [p for p in parcelas if p[2] != "Pago"]
    quantidade = len(pendentes)
    mensal = taxa_valor / 100
    if quantidade == 0:
        return
    if mensal == 0:
        valor_novo = round(saldo / quantidade, 2)
    else:
        valor_novo = round(saldo * mensal / (1 - (1 + mensal) ** (-quantidade)), 2)

    for parcela in pendentes:
        cursor.execute("""
            UPDATE PARCELA SET VALOR = ?, TAXA_APLICADA = ?
            WHERE ID_EMPRESTIMO = ? AND NUM_PARCELAS = ?
        """, (valor_novo, taxa_valor, id_emprestimo, parcela[0]))
        cursor.execute("""
            UPDATE MOV_FINANCEIRA SET VALOR = ?
            WHERE ID_USUARIO = ? AND DESCRICAO = ?
        """, (valor_novo, id_usuario,
              "Parcela de empréstimo " + str(id_emprestimo) + "-" + str(parcela[0])))


@app.route("/emprestimos")
def historico_emprestimos():
    if "usuario_id" not in session:
        flash("Faça login para acessar esta página.", "erro")
        return redirect(url_for("login"))

    periodo = request.args.get("periodo", "ultimos")
    if periodo not in PERIODOS:
        periodo = "ultimos"

    hoje = date.today()
    if periodo == "ultimos":
        data_inicio = hoje - timedelta(days=90)
        data_fim = hoje
    elif periodo == "proximos":
        data_inicio = hoje
        data_fim = hoje + timedelta(days=90)
    else:
        data_inicio = date(2000, 1, 1)
        data_fim = date(2100, 12, 31)

    conexao = conectar_banco()
    cursor = conexao.cursor()
    dados = []
    try:
        cursor.execute("""
            SELECT e.ID_EMPRESTIMO, e.DATA, s.VALOR_EMPRESTIMO,
                   s.NUM_PARCELAS, s.RISCO, e.STATUS
            FROM EMPRESTIMO e
            JOIN SIMULACAO s ON e.ID_SIMULACAO = s.ID_SIMULACAO
            WHERE s.ID_USUARIO = ? AND e.DATA BETWEEN ? AND ?
            ORDER BY e.DATA DESC, e.ID_EMPRESTIMO DESC
        """, (session["usuario_id"], data_inicio, data_fim))
        for linha in cursor.fetchall():
            data = linha[1].strftime("%d/%m/%Y") if isinstance(linha[1], (date, datetime)) else str(linha[1])
            dados.append({
                "id": linha[0],
                "data": data,
                "descricao": "Empréstimo",
                "classificacao": "Risco " + str(linha[4] or "Baixo"),
                "categoria": str(linha[3]) + " parcelas",
                "valor_texto": formatar_reais(float(linha[2] or 0)),
                "status": linha[5] or "Em andamento"
            })
    except Exception:
        app.logger.exception("Erro ao buscar histórico de empréstimos.")
        flash("Não foi possível carregar o histórico.", "erro")
    finally:
        cursor.close()
        conexao.close()

    return render_template("historico_emprestimos.html", dados=dados, periodo=periodo)


@app.route("/emprestimos/relatorio")
def relatorio_emprestimos():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    periodo = request.args.get("periodo", "ultimos")
    if periodo not in PERIODOS:
        periodo = "ultimos"
    hoje = date.today()
    if periodo == "ultimos":
        inicio, fim = hoje - timedelta(days=90), hoje
    elif periodo == "proximos":
        inicio, fim = hoje, hoje + timedelta(days=90)
    else:
        inicio, fim = date(2000, 1, 1), date(2100, 12, 31)

    conexao = conectar_banco()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT e.ID_EMPRESTIMO, e.DATA, s.VALOR_EMPRESTIMO,
               s.NUM_PARCELAS, s.RISCO, e.STATUS
        FROM EMPRESTIMO e JOIN SIMULACAO s ON e.ID_SIMULACAO = s.ID_SIMULACAO
        WHERE s.ID_USUARIO = ? AND e.DATA BETWEEN ? AND ?
        ORDER BY e.DATA DESC
    """, (session["usuario_id"], inicio, fim))
    linhas = cursor.fetchall()
    cursor.close()
    conexao.close()

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(190, 12, texto_pdf("Histórico de Empréstimos - CredMais"), ln=True, align="C")
    pdf.set_font("Arial", size=10)
    pdf.cell(190, 8, texto_pdf("Período: " + PERIODOS[periodo]), ln=True, align="C")
    pdf.ln(5)
    pdf.set_font("Arial", "B", 10)
    pdf.cell(35, 10, "Data", border=1)
    pdf.cell(65, 10, texto_pdf("Valor"), border=1)
    pdf.cell(35, 10, "Parcelas", border=1)
    pdf.cell(55, 10, "Risco / Status", border=1, ln=True)
    pdf.set_font("Arial", size=9)
    for item in linhas:
        data = item[1].strftime("%d/%m/%Y") if isinstance(item[1], (date, datetime)) else str(item[1])
        pdf.cell(35, 10, data, border=1)
        pdf.cell(65, 10, texto_pdf("R$ " + formatar_reais(float(item[2] or 0))), border=1)
        pdf.cell(35, 10, str(item[3]) + "x", border=1)
        pdf.cell(55, 10, texto_pdf(str(item[4]) + " / " + str(item[5])), border=1, ln=True)
    caminho = os.path.join(app.root_path, "relatorio_emprestimos.pdf")
    pdf.output(caminho)
    return send_file(caminho, as_attachment=True, mimetype="application/pdf")


@app.route("/emprestimos/<int:id_emprestimo>")
def visualizar_emprestimo(id_emprestimo):
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    conexao = conectar_banco()
    cursor = conexao.cursor()
    try:
        cursor.execute("""
            SELECT e.ID_EMPRESTIMO, e.DATA, e.STATUS, s.VALOR_EMPRESTIMO,
                   s.NUM_PARCELAS, s.VALOR_PARCELA, s.VALOR_TOTAL, s.RISCO
            FROM EMPRESTIMO e JOIN SIMULACAO s ON e.ID_SIMULACAO = s.ID_SIMULACAO
            WHERE e.ID_EMPRESTIMO = ? AND s.ID_USUARIO = ?
        """, (id_emprestimo, session["usuario_id"]))
        linha = cursor.fetchone()
        if not linha:
            flash("Empréstimo não encontrado.", "erro")
            return redirect(url_for("historico_emprestimos"))
        taxa_atual = buscar_taxa_por_ano(date.today().year)
        if taxa_atual:
            atualizar_parcelas_pendentes(cursor, id_emprestimo, session["usuario_id"], taxa_atual["juros"])
            conexao.commit()
        cursor.execute("""
            SELECT ID_PARCELA, NUM_PARCELAS, VALOR, DATA_VENCIMENTO, STATUS, TAXA_APLICADA
            FROM PARCELA WHERE ID_EMPRESTIMO = ? ORDER BY NUM_PARCELAS
        """, (id_emprestimo,))
        parcelas = cursor.fetchall()
        lista = []
        for p in parcelas:
            venc = p[3].strftime("%d/%m/%Y") if isinstance(p[3], (date, datetime)) else str(p[3])
            lista.append({
                "id": p[0], "numero": p[1], "valor": float(p[2] or 0),
                "vencimento": venc, "status": p[4] or "Pendente",
                "taxa": float(p[5]) if p[5] is not None else None,
                "valor_formatado": "R$ " + formatar_reais(float(p[2] or 0))
            })
        data = linha[1].strftime("%d/%m/%Y") if isinstance(linha[1], (date, datetime)) else str(linha[1])
        emprestimo = {
            "id": linha[0], "data": data, "status": linha[2],
            "valor": float(linha[3] or 0), "quantidade_parcelas": int(linha[4] or 0),
            "valor_parcela": float(linha[5] or 0), "total": float(linha[6] or 0),
            "risco": linha[7], "parcelas": int(linha[4] or 0), "lista_parcelas": lista,
            "valor_formatado": "R$ " + formatar_reais(float(linha[3] or 0)),
            "total_formatado": "R$ " + formatar_reais(float(linha[6] or 0)),
            "parcela_formatada": "R$ " + formatar_reais(float(linha[5] or 0))
        }
        taxa_atual = buscar_taxa_por_ano(date.today().year)
        return render_template("detalhes_emprestimos.html", emprestimo=emprestimo,
                               taxa_atual=taxa_atual["juros"] if taxa_atual else 0)
    finally:
        cursor.close()
        conexao.close()


@app.route("/parcela/<int:id_parcela>/pagar", methods=["POST"])
def pagar_parcela(id_parcela):
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    conexao = conectar_banco()
    cursor = conexao.cursor()
    try:
        cursor.execute("""
            SELECT p.ID_EMPRESTIMO, p.NUM_PARCELAS, p.VALOR, p.STATUS,
                   s.ID_USUARIO
            FROM PARCELA p
            JOIN EMPRESTIMO e ON p.ID_EMPRESTIMO = e.ID_EMPRESTIMO
            JOIN SIMULACAO s ON e.ID_SIMULACAO = s.ID_SIMULACAO
            WHERE p.ID_PARCELA = ?
        """, (id_parcela,))
        parcela = cursor.fetchone()
        if not parcela or parcela[4] != session["usuario_id"]:
            flash("Parcela não encontrada.", "erro")
            return redirect(url_for("historico_emprestimos"))
        if parcela[3] == "Pago":
            flash("Esta parcela já foi paga.", "erro")
            return redirect(url_for("visualizar_emprestimo", id_emprestimo=parcela[0]))

        taxa_atual = buscar_taxa_por_ano(date.today().year)
        taxa_valor = taxa_atual["juros"] if taxa_atual else 0

        # Registra a despesa somente quando a parcela é paga.
        descricao_antiga = "Parcela de empréstimo " + str(parcela[0]) + "-" + str(parcela[1])
        descricao_paga = "Parcela paga " + str(parcela[0]) + "-" + str(parcela[1])
        cursor.execute("""
            SELECT ID_MOV_FINANCEIRA
            FROM MOV_FINANCEIRA
            WHERE ID_USUARIO = ? AND DESCRICAO = ?
        """, (session["usuario_id"], descricao_antiga))
        despesa_antiga = cursor.fetchone()
        if despesa_antiga:
            cursor.execute("""
                UPDATE MOV_FINANCEIRA
                SET DATA_LANCAMENTO = ?, DESCRICAO = ?
                WHERE ID_MOV_FINANCEIRA = ?
            """, (date.today(), descricao_paga, despesa_antiga[0]))
        else:
            cursor.execute("""
                INSERT INTO MOV_FINANCEIRA
                    (TIPO, VALOR, DATA_LANCAMENTO, DESCRICAO, ID_USUARIO, CLASSIFICACAO)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (TIPO_DESPESA, parcela[2], date.today(), descricao_paga,
                  session["usuario_id"], 1))

        cursor.execute("""
            UPDATE PARCELA SET STATUS = 'Pago', TAXA_APLICADA = ?
            WHERE ID_PARCELA = ?
        """, (taxa_valor, id_parcela))

        # Atualiza os valores e a taxa somente das parcelas que ainda faltam.
        atualizar_parcelas_pendentes(cursor, parcela[0], session["usuario_id"], taxa_valor)

        cursor.execute("""
            UPDATE EMPRESTIMO SET STATUS = 'Concluído'
            WHERE ID_EMPRESTIMO = ?
              AND NOT EXISTS (SELECT 1 FROM PARCELA WHERE ID_EMPRESTIMO = ? AND STATUS <> 'Pago')
        """, (parcela[0], parcela[0]))
        conexao.commit()
        session["parcela_paga"] = {
            "numero": parcela[1], "valor": formatar_reais(float(parcela[2])),
            "data": date.today().strftime("%d/%m/%Y"), "taxa": taxa_valor
        }
        return redirect(url_for("parcela_paga"))
    except Exception:
        conexao.rollback()
        app.logger.exception("Erro ao pagar parcela.")
        flash("Não foi possível pagar a parcela.", "erro")
        return redirect(url_for("historico_emprestimos"))
    finally:
        cursor.close()
        conexao.close()


@app.route("/parcela-paga")
def parcela_paga():
    if "usuario_id" not in session:
        return redirect(url_for("login"))
    parcela = session.pop("parcela_paga", None)
    if not parcela:
        return redirect(url_for("historico_emprestimos"))
    return render_template("movimentacao_registrada.html", dados={
        "descricao": "Parcela paga - número " + str(parcela["numero"]),
        "valor_texto": parcela["valor"], "data": parcela["data"],
        "categoria": "Despesa", "classe": "despesa",
        "taxa": parcela["taxa"]
    })


@app.route("/emprestimos/detalhes")
def detalhes_emprestimos():
    if "usuario_id" not in session:
        flash("Faça login para acessar esta página.", "erro")
        return redirect(url_for("login"))

    emprestimo = session.get("emprestimo")

    if emprestimo:
        emprestimo = dict(emprestimo)
        emprestimo["lista_parcelas"] = gerar_parcelas(emprestimo)
        emprestimo["parcelas"] = emprestimo["quantidade_parcelas"]
        emprestimo["valor_formatado"] = "R$ " + formatar_reais(emprestimo["valor"])
        emprestimo["total_formatado"] = "R$ " + formatar_reais(emprestimo["total"])
        emprestimo["parcela_formatada"] = "R$ " + formatar_reais(emprestimo["valor_parcela"])

    return render_template(
        "detalhes_emprestimos.html",
        emprestimo=emprestimo
    )


@app.route("/emprestimo/realizado", methods=["POST"])
def emprestimo_realizado():
    if "usuario_id" not in session:
        flash("Faça login para acessar esta página.", "erro")
        return redirect(url_for("login"))

    cliente = request.form.get("cliente", "").strip()
    valor_texto = request.form.get("valor", "").strip()
    parcelas_texto = request.form.get("parcelas", "12").strip()
    data = request.form.get("data", "").strip()
    id_taxa_texto = request.form.get("id_taxa_juros", "").strip()

    try:
        valor = converter_valor(valor_texto)
        quantidade = int(parcelas_texto)

        if not cliente or valor <= 0 or quantidade < 1:
            raise ValueError

        if quantidade > 600:
            raise ValueError

        if data:
            data_objeto = datetime.strptime(data, "%Y-%m-%d")
            data_str = data_objeto.strftime("%d/%m/%Y")
            data_sql = data_objeto.date()
        else:
            data_objeto = datetime.today()
            data_str = data_objeto.strftime("%d/%m/%Y")
            data_sql = data_objeto.date()

        id_taxa_juros = int(id_taxa_texto)
        if id_taxa_juros <= 0:
            raise ValueError

    except (ValueError, TypeError, OverflowError):
        return "Dados inválidos. Confira os valores, a data e as parcelas.", 400

    id_usuario = session["usuario_id"]
    conexao = conectar_banco()
    cursor = conexao.cursor()

    try:
        # Usa a taxa cadastrada pelo administrador para o ano atual.
        cursor.execute("""
            SELECT FIRST 1 ID_TAXA_JUROS, TAXA_MENSAL
            FROM TAXA_JUROS
            WHERE EXTRACT(YEAR FROM DATA_REFERENCIA) = ?
            ORDER BY DATA_REFERENCIA DESC, ID_TAXA_JUROS DESC
        """, (date.today().year,))
        taxa_row = cursor.fetchone()
        if taxa_row is None:
            raise ValueError("Não existe taxa cadastrada para o ano atual.")

        id_taxa_juros = taxa_row[0]
        mensal = float(taxa_row[1]) / 100
        if mensal < 0 or not math.isfinite(mensal):
            raise ValueError("Taxa inválida.")
        if mensal == 0:
            valor_parcela = round(valor / quantidade, 2)
        else:
            valor_parcela = round(valor * mensal / (1 - (1 + mensal) ** (-quantidade)), 2)

        renda = somar_mes(TIPO_RECEITA)
        despesas = somar_mes(TIPO_DESPESA)
        renda_liquida = renda - despesas
        if renda_liquida <= 0:
            raise ValueError("A renda líquida precisa ser positiva.")

        comprometimento = (valor_parcela / renda_liquida) * 100
        if comprometimento <= 20:
            risco = "Baixo"
        elif comprometimento <= 35:
            risco = "Médio"
        else:
            risco = "Alto"
        if risco == "Alto":
            raise ValueError("Empréstimos de alto risco não podem ser realizados.")

        valor_total = round(valor_parcela * quantidade, 2)

        # 1. Salvar na tabela SIMULACAO
        cursor.execute(
            """
            INSERT INTO SIMULACAO (
                ID_USUARIO, ID_TAXA_JUROS, VALOR_EMPRESTIMO, NUM_PARCELAS, 
                VALOR_PARCELA, VALOR_TOTAL, PERCENTUAL_COMPROMETIDO, RISCO, DATA_SIMULACAO
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (id_usuario, id_taxa_juros, valor, quantidade, valor_parcela, valor_total, comprometimento, risco, data_sql)
        )

        # Buscar o ID da simulação gravada
        cursor.execute("SELECT MAX(ID_SIMULACAO) FROM SIMULACAO WHERE ID_USUARIO = ?", (id_usuario,))
        id_simulacao = cursor.fetchone()[0]

        # 2. Salvar na tabela EMPRESTIMO
        cursor.execute(
            """
            INSERT INTO EMPRESTIMO (ID_SIMULACAO, DATA, STATUS)
            VALUES (?, ?, ?)
            """,
            (id_simulacao, data_sql, 'Em andamento')
        )

        # Buscar o ID do empréstimo gravado
        cursor.execute("SELECT MAX(ID_EMPRESTIMO) FROM EMPRESTIMO")
        id_emprestimo = cursor.fetchone()[0]

        # 3. Gerar e salvar as parcelas na tabela PARCELA
        temp_emprestimo = {
            "data": data_str,
            "quantidade_parcelas": quantidade,
            "valor_parcela": valor_parcela,
            "parcelas_pagas": 0
        }
        lista_parcelas = gerar_parcelas(temp_emprestimo)

        for p in lista_parcelas:
            data_venc = datetime.strptime(p["vencimento"], "%d/%m/%Y").date()
            cursor.execute(
                """
                INSERT INTO PARCELA
                    (ID_EMPRESTIMO, NUM_PARCELAS, VALOR, DATA_VENCIMENTO, STATUS, TAXA_APLICADA)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (id_emprestimo, p["numero"], p["valor"], data_venc, p["status"], float(taxa_row[1]))
            )

        # Registrar o valor recebido e as parcelas nas movimentações financeiras
        cursor.execute(
            """
            INSERT INTO MOV_FINANCEIRA
            (TIPO, VALOR, DATA_LANCAMENTO, DESCRICAO, ID_USUARIO, CLASSIFICACAO)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (TIPO_RECEITA, valor, data_sql, "Empréstimo recebido", id_usuario, 2)
        )

        conexao.commit()

    except ValueError as erro_validacao:
        conexao.rollback()
        return str(erro_validacao), 400
    except Exception:
        conexao.rollback()
        app.logger.exception("Erro ao salvar empréstimo no banco.")
        return "Erro ao salvar empréstimo no banco de dados.", 500
    finally:
        cursor.close()
        conexao.close()

    session["emprestimo"] = {
        "cliente": cliente,
        "valor": round(valor, 2),
        "data": data_str,
        "quantidade_parcelas": quantidade,
        "valor_parcela": round(valor_parcela, 2),
        "total": valor_total,
        "status": "Em andamento",
        "parcelas_pagas": 0
    }

    session.modified = True

    return redirect(url_for("detalhes_emprestimos"))


@app.route("/emprestimo/limpar", methods=["POST"])
def limpar_emprestimo():
    session.pop("emprestimo", None)
    return redirect(url_for("detalhes_emprestimos"))


# ============================================================
# SIMULAÇÃO DE EMPRÉSTIMO
# ============================================================

@app.route("/simulacao", methods=["GET", "POST"])
def simulacao():
    if "usuario_id" not in session:
        flash("Faça login para simular um empréstimo.", "erro")
        return redirect(url_for("login"))

    erro = None
    resultado = None
    taxa = None

    try:
        renda = somar_mes(TIPO_RECEITA)
        despesas = somar_mes(TIPO_DESPESA)
    except Exception:
        app.logger.exception("Erro ao consultar as movimentações financeiras.")
        renda = 0
        despesas = 0
        erro = "Não foi possível consultar suas receitas e despesas cadastradas."

    renda_liquida = renda - despesas

    if request.method == "POST" and erro is None:
        try:
            valor_texto = request.form.get("valor", "").strip()
            parcelas_texto = request.form.get("parcelas", "").strip()

            valor = converter_valor(valor_texto)
            quantidade = int(parcelas_texto)

            if (not math.isfinite(valor) or valor <= 0 or
                    quantidade < 1 or quantidade > 600):
                raise ValueError

            if renda <= 0:
                erro = "Cadastre suas receitas deste mês em Movimentações antes de simular."
            elif renda_liquida <= 0:
                erro = "Suas despesas cadastradas são iguais ou maiores que suas receitas deste mês."

        except (ValueError, TypeError, OverflowError):
            erro = "Informe um valor de empréstimo e uma quantidade de parcelas válidos."

    if erro is None:
        try:
            taxa = buscar_taxa_por_ano(date.today().year)
        except Exception:
            app.logger.exception("Erro ao consultar as taxas.")
            erro = "Não foi possível consultar as taxas no banco de dados."

    if request.method == "POST" and erro is None:
        if taxa is None:
            erro = "Nenhuma taxa foi cadastrada no banco de dados."
        else:
            juros = taxa["juros"]
            mensal = juros / 100
            if mensal < 0 or not math.isfinite(mensal):
                erro = "A taxa cadastrada é inválida."
            else:
                if mensal == 0:
                    parcela = valor / quantidade
                else:
                    parcela = valor * mensal / (1 - (1 + mensal) ** (-quantidade))

                total = parcela * quantidade
                comprometimento = (parcela / renda_liquida) * 100

                if comprometimento <= 20:
                    risco = "Baixo"
                elif comprometimento <= 35:
                    risco = "Médio"
                else:
                    risco = "Alto"

                alto_risco = risco == "Alto"
                resultado = {
                    "valor": formatar_reais(valor),
                    "valor_original": round(valor, 2),
                    "parcelas": quantidade,
                    "juros": format(float(juros), ".2f").replace(".", ","),
                    "valor_parcela": formatar_reais(parcela),
                    "valor_parcela_original": round(parcela, 2),
                    "total": formatar_reais(total),
                    "comprometimento": formatar_reais(comprometimento),
                    "alto_risco": alto_risco,
                    "risco": risco
                }

                if alto_risco:
                    resultado[
                        "mensagem_risco"] = "A parcela compromete mais de 35% da sua renda mensal líquida. Não é possível realizar este empréstimo."

    if resultado is not None:
        return render_template("resultado_simulacao.html", resultado=resultado, taxa=taxa, erro=None)

    return render_template(
        "simulacao.html",
        resultado=None,
        taxa=taxa,
        erro=erro,
        renda_mes=formatar_reais(renda),
        despesas_mes=formatar_reais(despesas),
        renda_liquida_mes=formatar_reais(renda_liquida)
    )


@app.route("/admin/usuarios")
def gerenciar_usuarios():
    if int(session.get("usuario_tipo", 0)) != TIPO_ADMIN:
        flash("Acesso permitido apenas para administradores.", "erro")
        return redirect(url_for("dashboard"))
    conexao = conectar_banco()
    cursor = conexao.cursor()
    try:
        cursor.execute("""
            SELECT ID_USUARIO, NOME, EMAIL, TIPO, ATIVO, BLOQUEADO
            FROM USUARIO ORDER BY NOME
        """)
        usuarios = cursor.fetchall()
        total_usuarios = len(usuarios)
        perfis_ativos = sum(1 for usuario in usuarios if usuario[4] and not usuario[5])
        perfis_bloqueados = sum(1 for usuario in usuarios if usuario[5])
    finally:
        cursor.close()
        conexao.close()
    return render_template(
        "gerenciar_usuarios.html", usuarios=usuarios,
        total_usuarios=total_usuarios, perfis_ativos=perfis_ativos,
        perfis_bloqueados=perfis_bloqueados
    )

@app.route("/admin/usuarios/<int:id_usuario>", methods=["GET", "POST"])
def editar_usuario_admin(id_usuario):
    if int(session.get("usuario_tipo", 0)) != TIPO_ADMIN:
        return redirect(url_for("dashboard"))

    conexao = conectar_banco()
    cursor = conexao.cursor()
    try:
        cursor.execute("SELECT NOME, EMAIL, SENHA, FOTO_PERFIL, TIPO, ATIVO, BLOQUEADO FROM USUARIO WHERE ID_USUARIO = ?", (id_usuario,))
        usuario = cursor.fetchone()
        if not usuario:
            return redirect(url_for("gerenciar_usuarios"))

        if request.method == "POST":
            nome = request.form.get("nome", "").strip()
            email = request.form.get("email", "").strip().lower()
            tipo = request.form.get("tipo", "1")
            nova_senha = request.form.get("nova_senha", "")
            foto = request.files.get("foto")
            foto_nome = usuario[3]

            if not any(c.isalpha() for c in nome) or tipo not in ("1", "2"):
                flash("Confira o nome e o tipo do usuário.", "erro")
            else:
                cursor.execute("SELECT ID_USUARIO FROM USUARIO WHERE EMAIL = ? AND ID_USUARIO <> ?", (email, id_usuario))
                if cursor.fetchone():
                    flash("Este e-mail já está cadastrado.", "erro")
                else:
                    if foto and foto.filename:
                        extensao = os.path.splitext(foto.filename)[1].lower()
                        if extensao not in (".jpg", ".jpeg", ".png", ".webp"):
                            flash("Escolha uma imagem JPG, JPEG, PNG ou WEBP.", "erro")
                            return render_template("editar_usuario_admin.html", nome=usuario[0], email=usuario[1], foto_perfil=usuario[3] or "", tipo=usuario[4], id_usuario=id_usuario, bloqueado=bool(usuario[6]), ativo=bool(usuario[5]))
                        foto_nome = "perfil_" + str(id_usuario) + "_" + uuid4().hex + extensao
                        pasta = os.path.join(app.root_path, "static", "uploads")
                        os.makedirs(pasta, exist_ok=True)
                        foto.save(os.path.join(pasta, foto_nome))

                    if nova_senha:
                        senha_hash = generate_password_hash(nova_senha)
                        cursor.execute("""
                            INSERT INTO HISTORICO_SENHA (SENHA, ID_USUARIO, DATA_ALTERACAO)
                            VALUES (?, ?, ?)
                        """, (usuario[2], id_usuario, datetime.now()))
                        cursor.execute("""
                            UPDATE USUARIO SET NOME = ?, EMAIL = ?, TIPO = ?, SENHA = ?, FOTO_PERFIL = ?
                            WHERE ID_USUARIO = ?
                        """, (nome, email, int(tipo), senha_hash, foto_nome, id_usuario))
                    else:
                        cursor.execute("""
                            UPDATE USUARIO SET NOME = ?, EMAIL = ?, TIPO = ?, FOTO_PERFIL = ?
                            WHERE ID_USUARIO = ?
                        """, (nome, email, int(tipo), foto_nome, id_usuario))
                    conexao.commit()
                    if id_usuario == session.get("usuario_id"):
                        session["usuario_nome"] = nome
                        session["usuario_email"] = email
                        session["usuario_tipo"] = int(tipo)
                    flash("Usuário atualizado.", "sucesso")
                    return redirect(url_for("gerenciar_usuarios"))

        return render_template("editar_usuario_admin.html",
                               nome=usuario[0], email=usuario[1],
                               foto_perfil=usuario[3] or "",
                               tipo=usuario[4], id_usuario=id_usuario, bloqueado=bool(usuario[6]), ativo=bool(usuario[5]))
    finally:
        cursor.close()
        conexao.close()


@app.route("/admin/usuarios/<int:id_usuario>/excluir", methods=["POST"])
def excluir_usuario_admin(id_usuario):
    if int(session.get("usuario_tipo", 0)) != TIPO_ADMIN:
        return redirect(url_for("dashboard"))
    if id_usuario == session.get("usuario_id"):
        flash("Não é possível excluir sua própria conta por esta tela.", "erro")
        return redirect(url_for("gerenciar_usuarios"))
    conexao = conectar_banco()
    cursor = conexao.cursor()
    try:
        cursor.execute("SELECT BLOQUEADO FROM USUARIO WHERE ID_USUARIO = ?", (id_usuario,))
        status_usuario = cursor.fetchone()
        if status_usuario and status_usuario[0]:
            cursor.execute("""
                UPDATE USUARIO
                SET BLOQUEADO = ?, TENTATIVAS_LOGIN = ?
                WHERE ID_USUARIO = ?
            """, (False, 0, id_usuario))
            conexao.commit()
            flash("Perfil desbloqueado com sucesso.", "sucesso")
            return redirect(url_for("gerenciar_usuarios"))

        cursor.execute("SELECT ID_SIMULACAO FROM SIMULACAO WHERE ID_USUARIO = ?", (id_usuario,))
        simulacoes = [x[0] for x in cursor.fetchall()]
        for id_simulacao in simulacoes:
            cursor.execute("SELECT ID_EMPRESTIMO FROM EMPRESTIMO WHERE ID_SIMULACAO = ?", (id_simulacao,))
            emprestimos = [x[0] for x in cursor.fetchall()]
            for id_emp in emprestimos:
                cursor.execute("DELETE FROM PARCELA WHERE ID_EMPRESTIMO = ?", (id_emp,))
            cursor.execute("DELETE FROM EMPRESTIMO WHERE ID_SIMULACAO = ?", (id_simulacao,))
        cursor.execute("DELETE FROM SIMULACAO WHERE ID_USUARIO = ?", (id_usuario,))
        cursor.execute("DELETE FROM MOV_FINANCEIRA WHERE ID_USUARIO = ?", (id_usuario,))
        cursor.execute("DELETE FROM HISTORICO_SENHA WHERE ID_USUARIO = ?", (id_usuario,))
        cursor.execute("DELETE FROM USUARIO WHERE ID_USUARIO = ?", (id_usuario,))
        conexao.commit()
        flash("Usuário excluído.", "sucesso")
    except Exception:
        conexao.rollback()
        app.logger.exception("Erro ao excluir usuário.")
        flash("Não foi possível excluir o usuário.", "erro")
    finally:
        cursor.close()
        conexao.close()
    return redirect(url_for("gerenciar_usuarios"))


# ============================================================
# EXECUÇÃO
# ============================================================

if __name__ == "__main__":
    app.run(debug=True)