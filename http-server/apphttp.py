#!/usr/bin/python3

"""
Aplicacao que simula um servidor HTTP em Python que sera usado como um microservico
em containers Docker

Copyright (c) 2021 Universidade do Minho
Perfil GVR - Virtualizacao de Redes 2020/21
Desenvolvido por: Nelson Faria (a84727@alunos.uminho.pt)
"""

import os, sys, datetime, logging
import requests
import jwt, json, socket
from werkzeug.utils import secure_filename
from flask import Flask, request, url_for, redirect, render_template, make_response, send_from_directory, current_app
from dotenv import load_dotenv


app = Flask(__name__)

# LOcalizacao dos ficheiros relativos a aplicacao(ficam no volume docker)
UPDIRECTORY = "/usr/src/http"
# Nome do ficheiro de logs
logname = "/http-server/logs/logs.txt"

# Extensoes permitidas para o download de ficheiros 
EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg'])

app.config['UPDIRECTORY'] = UPDIRECTORY

# IP do servidor de autenticacao
auth_ip = socket.gethostbyname("auth_container")
# IP do servidor de HTTP
http_ip = socket.gethostbyname("http_container")
# Porta do servidor autenticacao
auth_port = 5000
# Porta do servidor HTTP
http_port = 8888


'''
Verifica se a extensao do ficheiro se encontra dentro das extensoes permitidas
'''
def isValidFile(file):

	return '.' in file and \
		file.rsplit('.', 1)[1].lower() in EXTENSIONS


'''
Fazer o decoding de um token, retornando o nome do user e o seu papel
'''
def decode_token(enctoken):

	try:
		payload = jwt.decode(enctoken, 
			options={"verify_signature": False}, 
			algorithms=["HS256"])
		return payload
	except jwt.ExpiredSignatureError:
		return 'Signature expired. Please log in again.'
	except jwt.InvalidTokenError:
		return 'Invalid token. Please log in again.'


'''
Usado para verificar a existencia e validade de um token
'''
def verificaToken(token):

	# Verificar se o token existe nos cookies
	try:
		token_dec = decode_token(token)
		payload = {'username': token_dec["user"], 'token': token}
		# Verificar se e o mesmo que esta na base de dados
		result = requests.post('http://' + auth_ip + ':' + str(auth_port) + '/verificaToken', data=json.dumps(payload))
		return result.status_code == requests.codes.ok

	except Exception as e:
		return False


'''
Funcao usada para proceder ao tratamento das operacoes relativas ao path /download/<path:filename>
(Usado aquando de um download de um ficheiro)
'''
@app.route('/download/<path:filename>', methods=['GET', 'POST'])
def download(filename):

	try:
		# Buscar o token que esta nos cookies
		token = request.cookies.get('token')
		# Verificar se o token existe e e valido
		if verificaToken(token) == False:
			return redirect(url_for('home'))
		ficheiros = os.path.join(app.config['UPDIRECTORY'])
		return send_from_directory(directory=ficheiros, filename=filename)

	except Exception as e:
		return redirect('http://' + auth_ip + ':' + str(auth_port) + '/login')


'''
Funcao usada para proceder ao tratamento das operacoes relativas ao path /upload
(Usado aquando de um upload de um ficheiro)
'''
@app.route('/upload', methods=['POST'])
def upload():

	try:
		# Buscar o token que esta nos cookies
		token = request.cookies.get('token')
		# Verificar se o token existe e e valido
		if verificaToken(token) == False:
			return redirect(url_for('home'))
		# Verificar se 'file' esta no pedido
		if 'file' not in request.files:
			return redirect(url_for('home'))
		# Pegar no ficheiro
		f = request.files['file']

		# Efetuar o upload do ficheiro
		if f and isValidFile(f.filename):
			filename = secure_filename(f.filename)
			f.save(os.path.join(app.config['UPDIRECTORY'], filename))
		return redirect(url_for('home'))

	except Exception as e:
		return redirect('http://' + auth_ip + ':' + str(auth_port) + '/login')


'''
Funcao usada para validar os resultados que advem do login
'''
@app.route('/validaLogin', methods=['GET'])
def validaLogin():

	token = request.args.get('token')
	# Verificar se o token existe e e valido
	if verificaToken(token) == False:
		return redirect(url_for('home'))
	# Set cookie policy for session cookie.
	expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=30, seconds=0)
	# Se o token nao for valido, redirecionar para a home
	if not token:
		return redirect(url_for('home'))
	else:
		# Redirecionar para o admin de modo a verificar se e administrador
		res = make_response(redirect(url_for('admin')))
		res.set_cookie("token", token, expires=expires)
		return res


'''
Funcao usada para proceder ao tratamento das operacoes relativas ao path /
'''
@app.route('/', methods=['GET','POST'])
def home():

	try:
		# Buscar o token que esta nos cookies
		token = request.cookies.get('token')
		# Verificar se o token existe e e valido
		if verificaToken(token) == False:
			return redirect('http://' + auth_ip + ':' + str(auth_port) + '/login')
		token_dec = decode_token(token)
		# Verificar se estamos perante um user ou um admin, 
		# senao houver token ira ser redirecionado para o login na autenticacao
		if token_dec["role"] == "user":
			return redirect(url_for('user'))
		elif token_dec["role"] == "admin":
			return redirect(url_for('admin'))

	except Exception as error:
		return redirect('http://' + auth_ip + ':' + str(auth_port) + '/login')


'''
Funcao usada para proceder ao tratamento das operacoes relativas ao path /admin
'''
@app.route('/admin', methods=['GET','POST'])
def admin():

	try:
		# Buscar o token que esta nos cookies
		token = request.cookies.get('token')
		# Verificar se o token existe e e valido
		if verificaToken(token) == False:
			return redirect(url_for('home'))
		token_dec = decode_token(token)
		# Se for um user, redirecionar para la
		if token_dec["role"] == "user":
			return redirect(url_for('user'))

	except Exception as error:
		# Redirecionado para a home caso nao tenha token
		return redirect(url_for('home'))

	# Obter a lista de ficheiros que esta na pasta de uploads
	file_list = []
	for f in os.listdir(app.config['UPDIRECTORY']):
		file_list.append(f)

	return render_template("admin.html", files=file_list)


'''
Funcao usada para proceder ao tratamento das operacoes relativas ao path /user
'''
@app.route('/user', methods=['GET'])
def user():

	try:
		# Buscar o token que esta nos cookies
		token = request.cookies.get('token')
		# Verificar se o token existe e e valido
		if verificaToken(token) == False:
			return redirect(url_for('home'))
		token_dec = decode_token(token)
		# Se for um user, redirecionar para la
		if token_dec["role"] == "admin":
			return redirect(url_for('admin'))
	except Exception as error:
		return redirect('http://' + auth_ip + ':' + str(auth_port) + '/login')
	# Criar a lista de ficheiros a serem mostrados para o user
	file_list = []
	for f in os.listdir(app.config['UPDIRECTORY']):
		# Cria o link html
		file_list.append(f)

	return render_template("user.html", files=file_list)


'''
Funcao usada para proceder ao tratamento das operacoes relativas ao path /
'''
@app.route('/logout', methods=['POST'])
def logout():

	try:
		res = make_response(redirect(url_for('home')))
		# Apagar o token
		res.set_cookie('token', '', expires=0)
		return res

	except Exception as error:
		return redirect('http://' + auth_ip + ':' + str(auth_port) + '/login')


if __name__ == '__main__':

	# configuracao de log
	logging.basicConfig(filename=logname,
							filemode='a',
							format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
							datefmt='%H:%M:%S',
							level=logging.DEBUG)

	logging.info("Running HTTP Server")
	logger = logging.getLogger()
	# fim configuracao de log
	app.run(host='0.0.0.0', port=http_port, debug=True)
