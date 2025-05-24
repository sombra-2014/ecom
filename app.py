import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from werkzeug.utils import secure_filename # Para manejar nombres de archivos de forma segura

# --- Configuración de la Aplicación ---
app = Flask(__name__)

# Configuración de la base de datos SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecommerce.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'una_clave_secreta_muy_segura_para_el_ecommerce_con_sesiones' # Clave secreta para sesiones y seguridad
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads') # Carpeta para subir imágenes
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'} # Extensiones de archivo permitidas

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Vista a la que redirigir si no está logueado

# Asegúrate de que la carpeta de subidas exista
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- Modelos de Base de Datos ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    orders = db.relationship('Order', backref='user', lazy=True) # Relación con pedidos

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(120), nullable=False)
    precio = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False, default=0)
    imagen = db.Column(db.String(120), nullable=True) # Nombre del archivo de imagen

    def __repr__(self):
        return f'<Product {self.nombre}>'

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # Puede ser nulo si es invitado
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default='Completado') # Ejemplo: 'Completado', 'Pendiente', 'Enviado'

    # Una orden tiene múltiples OrderItems
    items = db.relationship('OrderItem', backref='order', lazy=True)

    def __repr__(self):
        return f'<Order {self.id} - Total: {self.total_amount}>'

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, nullable=False) # Guardamos el ID del producto
    product_name_at_purchase = db.Column(db.String(120), nullable=False) # Guardamos el nombre al momento de la compra
    quantity = db.Column(db.Integer, nullable=False)
    price_at_purchase = db.Column(db.Float, nullable=False) # Guardamos el precio al momento de la compra

    def __repr__(self):
        return f'<OrderItem {self.id} - Prod: {self.product_name_at_purchase} - Qty: {self.quantity}>'


# --- Funciones de Flask-Login ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Rutas de la Aplicación ---

# Función para verificar extensiones de archivo permitidas
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.before_first_request
def create_tables():
    db.create_all()
    # Crear usuario administrador por defecto si no existe
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', is_admin=True)
        admin_user.set_password('superseguracontraseña123')
        db.session.add(admin_user)
        db.session.commit()
        print("Usuario administrador 'admin' creado.")
    else:
        print("El usuario administrador 'admin' ya existe.")


@app.route('/')
def landing_page():
    return render_template('landing_page.html')

@app.route('/products')
def products_page():
    products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    product = Product.query.get(product_id)
    if not product:
        flash('Producto no encontrado.', 'error')
        return redirect(url_for('products_page'))

    if 'cart' not in session:
        session['cart'] = {}

    # Convertir product.id a string para usar como clave en el diccionario de la sesión
    # Esto evita problemas si los IDs no son siempre enteros en el futuro o si se mezclan tipos de claves
    product_id_str = str(product.id) 

    if product_id_str in session['cart']:
        session['cart'][product_id_str]['quantity'] += 1
    else:
        session['cart'][product_id_str] = {
            'name': product.nombre,
            'price': product.precio,
            'quantity': 1,
            'image': product.imagen # Guardamos la imagen en la sesión para el carrito
        }
    
    session.modified = True # Importante para que Flask guarde los cambios en el diccionario de la sesión
    flash(f'{product.nombre} añadido al carrito.', 'success')
    return redirect(url_for('products_page'))

@app.route('/view_cart')
def view_cart():
    cart = session.get('cart', {})
    
    # Calcular el total del carrito
    total = sum(item['price'] * item['quantity'] for item in cart.values())
    
    return render_template('cart.html', cart=cart, total=total)

@app.route('/update_cart', methods=['POST'])
def update_cart():
    product_id = request.form.get('product_id')
    action = request.form.get('action')
    cart = session.get('cart', {})

    if product_id not in cart:
        flash('Producto no encontrado en el carrito.', 'error')
        return redirect(url_for('view_cart'))

    if action == 'increase':
        # Verificar stock antes de aumentar la cantidad
        product_db = Product.query.get(int(product_id))
        if product_db and cart[product_id]['quantity'] < product_db.stock:
            cart[product_id]['quantity'] += 1
            flash(f'Cantidad de {cart[product_id]["name"]} aumentada.', 'info')
        else:
            flash(f'No hay suficiente stock de {cart[product_id]["name"]}.', 'error')
    elif action == 'decrease':
        cart[product_id]['quantity'] -= 1
        if cart[product_id]['quantity'] <= 0:
            del cart[product_id]
            flash('Producto eliminado del carrito.', 'success')
        else:
            flash(f'Cantidad de {cart[product_id]["name"]} disminuida.', 'info')
    elif action == 'remove':
        del cart[product_id]
        flash('Producto eliminado del carrito.', 'success')
    
    session['cart'] = cart # Actualiza la sesión con el carrito modificado
    session.modified = True # Asegura que Flask guarde los cambios
    return redirect(url_for('view_cart'))

@app.route('/checkout')
def checkout():
    cart = session.get('cart', {})
    if not cart:
        flash('Tu carrito está vacío.', 'error')
        return redirect(url_for('products_page'))

    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())

    try:
        # 1. Crear una nueva orden (Order)
        # Si el usuario está logueado, asociamos el pedido a su ID
        user_id = current_user.id if current_user.is_authenticated else None
        new_order = Order(user_id=user_id, total_amount=total_amount, status='Completado')
        db.session.add(new_order)
        db.session.flush() # Esto asigna un ID al new_order antes del commit

        # 2. Crear los ítems de la orden (OrderItem)
        for product_id_str, item_data in cart.items():
            # Convertir product_id_str a int para buscar en la base de datos si es necesario
            product_id_int = int(product_id_str)
            
            # Obtener el producto actual para asegurarse del stock
            product_db = Product.query.get(product_id_int)

            if not product_db or product_db.stock < item_data['quantity']:
                db.session.rollback() # Si hay un problema de stock, deshacer todo
                flash(f'Stock insuficiente para {item_data["name"]}. La compra no pudo completarse.', 'error')
                return redirect(url_for('view_cart'))

            # Reducir el stock del producto
            product_db.stock -= item_data['quantity']
            db.session.add(product_db) # Marcar el producto como modificado

            # Crear el OrderItem
            order_item = OrderItem(
                order_id=new_order.id,
                product_id=product_id_int,
                product_name_at_purchase=item_data['name'],
                quantity=item_data['quantity'],
                price_at_purchase=item_data['price']
            )
            db.session.add(order_item)

        db.session.commit() # Confirmar todas las operaciones a la base de datos

        # Vaciar el carrito después de la compra exitosa
        session.pop('cart', None)
        session.modified = True
        
        flash('¡Compra finalizada con éxito! Gracias por tu pedido.', 'success')
        return redirect(url_for('products_page'))

    except Exception as e:
        db.session.rollback() # En caso de cualquier error, deshacer la transacción
        print(f"Error al procesar la compra: {e}")
        flash('Hubo un error al procesar tu compra. Por favor, intenta de nuevo.', 'error')
        return redirect(url_for('view_cart'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Inicio de sesión exitoso.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Nombre de usuario o contraseña incorrectos.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('landing_page'))

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Acceso denegado. Solo administradores.', 'error')
        return redirect(url_for('login'))
    products = Product.query.all() # Para mostrar los productos en el dashboard
    return render_template('admin.html', products=products)

@app.route('/admin/add_product', methods=['GET', 'POST'])
@login_required
def admin_add_product():
    if not current_user.is_admin:
        flash('Acceso denegado. Solo administradores.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        nombre = request.form.get('nombre')
        precio = float(request.form.get('precio'))
        stock = int(request.form.get('stock'))
        imagen_file = request.files.get('imagen') # Obtener el archivo de imagen

        filename = None
        if imagen_file and allowed_file(imagen_file.filename):
            filename = secure_filename(imagen_file.filename)
            imagen_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        new_product = Product(nombre=nombre, precio=precio, stock=stock, imagen=filename)
        db.session.add(new_product)
        db.session.commit()
        flash('Producto añadido con éxito!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_add_product.html')

@app.route('/admin/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_product(product_id):
    if not current_user.is_admin:
        flash('Acceso denegado. Solo administradores.', 'error')
        return redirect(url_for('login'))

    product = Product.query.get_or_404(product_id)

    if request.method == 'POST':
        product.nombre = request.form.get('nombre')
        product.precio = float(request.form.get('precio'))
        product.stock = int(request.form.get('stock'))
        
        imagen_file = request.files.get('imagen')
        if imagen_file and allowed_file(imagen_file.filename):
            # Opcional: eliminar imagen antigua si existe
            if product.imagen:
                old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.imagen)
                if os.path.exists(old_image_path):
                    os.remove(old_image_path)
            
            filename = secure_filename(imagen_file.filename)
            imagen_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            product.imagen = filename
        
        db.session.commit()
        flash('Producto actualizado con éxito!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_edit_product.html', product=product)

@app.route('/admin/delete_product/<int:product_id>', methods=['POST'])
@login_required
def admin_delete_product(product_id):
    if not current_user.is_admin:
        flash('Acceso denegado. Solo administradores.', 'error')
        return redirect(url_for('login'))

    product = Product.query.get_or_404(product_id)
    
    try:
        # Eliminar la imagen asociada si existe
        if product.imagen:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.imagen)
            if os.path.exists(image_path):
                os.remove(image_path)

        db.session.delete(product)
        db.session.commit()
        flash('Producto eliminado con éxito!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar producto: {e}', 'error')
    
    return redirect(url_for('admin_dashboard'))

# --- NUEVAS RUTAS DE GESTIÓN DE PEDIDOS ---
@app.route('/admin/orders')
@login_required
def admin_orders():
    if not current_user.is_admin:
        flash('Acceso denegado. Solo administradores.', 'error')
        return redirect(url_for('login'))

    orders = Order.query.order_by(Order.date_created.desc()).all()
    return render_template('admin_orders.html', orders=orders)

@app.route('/admin/orders/<int:order_id>')
@login_required
def admin_order_details(order_id):
    if not current_user.is_admin:
        flash('Acceso denegado. Solo administradores.', 'error')
        return redirect(url_for('login'))

    order = Order.query.get_or_404(order_id)
    return render_template('admin_order_details.html', order=order, order_items=order.items)


if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Asegura que las tablas se creen al iniciar la app si no existen
    app.run(debug=True, host='0.0.0.0')