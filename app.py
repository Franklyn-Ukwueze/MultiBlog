from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime
import os
from functools import wraps
import hashlib
import secrets
import base64

app = Flask(__name__)
CORS(app)

# MongoDB connection
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
client = MongoClient(MONGO_URI)
db = client['multi_blog_db']

# Collections
admins = db['admins']
blogs = db['blogs']
posts = db['posts']
comments = db['comments']

# Create indexes
admins.create_index('email', unique=True)
blogs.create_index('admin_id')
posts.create_index([('blog_id', 1), ('created_at', -1)])
comments.create_index([('post_id', 1), ('created_at', -1)])

# Helper functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_session_token():
    return secrets.token_urlsafe(32)

def serialize_doc(doc):
    if doc:
        doc['_id'] = str(doc['_id'])
        if 'blog_id' in doc:
            doc['blog_id'] = str(doc['blog_id'])
        if 'post_id' in doc:
            doc['post_id'] = str(doc['post_id'])
        if 'admin_id' in doc:
            doc['admin_id'] = str(doc['admin_id'])
        # Remove sensitive data
        doc.pop('password_hash', None)
    return doc

# Auth decorator
def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid authorization'}), 401
        
        token = auth_header.split(' ')[1]
        admin = admins.find_one({'session_token': token})
        
        if not admin:
            return jsonify({'error': 'Invalid or expired session'}), 401
        
        request.admin = admin
        return f(*args, **kwargs)
    return decorated

# Check if admin owns the blog
def verify_blog_ownership(admin_id, blog_id):
    blog = blogs.find_one({'_id': ObjectId(blog_id), 'admin_id': ObjectId(admin_id)})
    return blog is not None

# ===== ADMIN MANAGEMENT =====

@app.route('/api/admin/register', methods=['POST'])
def register_admin():
    """Register a new admin account"""
    data = request.json
    
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')
    
    if not email or not password or not name:
        return jsonify({'error': 'Email, password, and name are required'}), 400
    
    # Check if admin already exists
    if admins.find_one({'email': email}):
        return jsonify({'error': 'Admin with this email already exists'}), 409
    
    admin_doc = {
        'email': email,
        'password_hash': hash_password(password),
        'name': name,
        'created_at': datetime.utcnow()
    }
    
    result = admins.insert_one(admin_doc)
    
    return jsonify({
        'message': 'Admin registered successfully',
        'admin_id': str(result.inserted_id)
    }), 201

@app.route('/api/admin/login', methods=['POST'])
def login_admin():
    """Admin login - returns session token"""
    data = request.json
    
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400
    
    admin = admins.find_one({'email': email})
    
    if not admin or admin['password_hash'] != hash_password(password):
        return jsonify({'error': 'Invalid email or password'}), 401
    
    # Generate session token
    session_token = generate_session_token()
    admins.update_one(
        {'_id': admin['_id']},
        {'$set': {'session_token': session_token, 'last_login': datetime.utcnow()}}
    )
    
    return jsonify({
        'message': 'Login successful',
        'session_token': session_token,
        'admin': {
            'id': str(admin['_id']),
            'email': admin['email'],
            'name': admin['name']
        }
    }), 200

@app.route('/api/admin/logout', methods=['POST'])
@require_admin
def logout_admin():
    """Admin logout - invalidates session token"""
    admins.update_one(
        {'_id': request.admin['_id']},
        {'$unset': {'session_token': ''}}
    )
    
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/admin/profile', methods=['GET'])
@require_admin
def get_admin_profile():
    """Get current admin profile"""
    admin = serialize_doc(request.admin.copy())
    return jsonify(admin), 200

# ===== BLOG MANAGEMENT =====

@app.route('/api/blogs', methods=['POST'])
@require_admin
def create_blog():
    """Create a new blog (admin only)"""
    data = request.json
    
    # Validation
    if not data.get('name'):
        return jsonify({'error': 'Blog name is required'}), 400
    
    categories = data.get('categories', [])
    if not isinstance(categories, list):
        return jsonify({'error': 'Categories must be an array'}), 400
    
    blog_doc = {
        'admin_id': request.admin['_id'],
        'name': data.get('name'),
        'description': data.get('description', ''),
        'categories': categories,
        'created_at': datetime.utcnow()
    }
    
    result = blogs.insert_one(blog_doc)
    blog_doc['_id'] = str(result.inserted_id)
    
    return jsonify({
        'message': 'Blog created successfully',
        'blog': serialize_doc(blog_doc)
    }), 201

@app.route('/api/blogs', methods=['GET'])
@require_admin
def get_admin_blogs():
    """Get all blogs owned by the current admin"""
    blog_list = list(blogs.find({'admin_id': request.admin['_id']}))
    
    return jsonify({
        'blogs': [serialize_doc(b) for b in blog_list]
    }), 200

@app.route('/api/blogs/<blog_id>', methods=['GET'])
def get_blog(blog_id):
    """Get blog details (public)"""
    try:
        blog = blogs.find_one({'_id': ObjectId(blog_id)})
    except:
        return jsonify({'error': 'Invalid blog ID format'}), 400
    
    if not blog:
        return jsonify({'error': 'Blog not found'}), 404
    
    return jsonify(serialize_doc(blog)), 200

@app.route('/api/blogs/<blog_id>', methods=['PUT'])
@require_admin
def update_blog(blog_id):
    """Update blog (admin only)"""
    if not verify_blog_ownership(request.admin['_id'], blog_id):
        return jsonify({'error': 'Unauthorized - you do not own this blog'}), 403
    
    data = request.json
    update_fields = {}
    
    if 'name' in data:
        update_fields['name'] = data['name']
    if 'description' in data:
        update_fields['description'] = data['description']
    if 'categories' in data:
        if not isinstance(data['categories'], list):
            return jsonify({'error': 'Categories must be an array'}), 400
        update_fields['categories'] = data['categories']
    
    if not update_fields:
        return jsonify({'error': 'No fields to update'}), 400
    
    blogs.update_one(
        {'_id': ObjectId(blog_id)},
        {'$set': update_fields}
    )
    
    return jsonify({'message': 'Blog updated successfully'}), 200

@app.route('/api/blogs/<blog_id>', methods=['DELETE'])
@require_admin
def delete_blog(blog_id):
    """Delete blog and all associated content (admin only)"""
    if not verify_blog_ownership(request.admin['_id'], blog_id):
        return jsonify({'error': 'Unauthorized - you do not own this blog'}), 403
    
    # Delete blog, all posts, and all comments
    result = blogs.delete_one({'_id': ObjectId(blog_id)})
    
    if result.deleted_count == 0:
        return jsonify({'error': 'Blog not found'}), 404
    
    post_ids = [p['_id'] for p in posts.find({'blog_id': ObjectId(blog_id)})]
    posts.delete_many({'blog_id': ObjectId(blog_id)})
    comments.delete_many({'blog_id': ObjectId(blog_id)})
    
    return jsonify({'message': 'Blog and all associated content deleted'}), 200

# ===== POST MANAGEMENT =====

@app.route('/api/blogs/<blog_id>/posts', methods=['POST'])
@require_admin
def create_post(blog_id):
    """Create a new post (admin only)"""
    if not verify_blog_ownership(request.admin['_id'], blog_id):
        return jsonify({'error': 'Unauthorized - you do not own this blog'}), 403
    
    data = request.json
    
    # Validation
    if not data.get('title') or not data.get('content'):
        return jsonify({'error': 'Title and content are required'}), 400
    
    # Validate category if provided
    category = data.get('category')
    if category:
        blog = blogs.find_one({'_id': ObjectId(blog_id)})
        if category not in blog.get('categories', []):
            return jsonify({'error': f'Invalid category. Must be one of: {", ".join(blog.get("categories", []))}'}), 400
    
    post_doc = {
        'blog_id': ObjectId(blog_id),
        'title': data.get('title'),
        'excerpt': data.get('excerpt', ''),
        'content': data.get('content'),
        'category': category,
        'image': data.get('image'),  # Base64 encoded or URL
        'author': data.get('author', request.admin['name']),
        'likes': 0,
        'created_at': datetime.utcnow(),
        'updated_at': datetime.utcnow()
    }
    
    result = posts.insert_one(post_doc)
    post_doc['_id'] = str(result.inserted_id)
    
    return jsonify({
        'message': 'Post created successfully',
        'post': serialize_doc(post_doc)
    }), 201

@app.route('/api/blogs/<blog_id>/posts', methods=['GET'])
def get_posts(blog_id):
    """Get all posts for a blog (public) - supports filtering by category"""
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        category = request.args.get('category')  # Optional filter
    except ValueError:
        return jsonify({'error': 'Invalid page or limit parameter'}), 400
    
    if page < 1 or limit < 1 or limit > 100:
        return jsonify({'error': 'Page must be >= 1 and limit must be between 1 and 100'}), 400
    
    skip = (page - 1) * limit
    
    # Build query
    query = {'blog_id': ObjectId(blog_id)}
    if category:
        query['category'] = category
    
    try:
        post_list = list(posts.find(query).sort('created_at', -1).skip(skip).limit(limit))
    except:
        return jsonify({'error': 'Invalid blog ID format'}), 400
    
    total = posts.count_documents(query)
    
    return jsonify({
        'posts': [serialize_doc(p) for p in post_list],
        'total': total,
        'page': page,
        'pages': (total + limit - 1) // limit,
        'category': category
    }), 200

@app.route('/api/posts/<post_id>', methods=['GET'])
def get_post(post_id):
    """Get a single post (public)"""
    try:
        post = posts.find_one({'_id': ObjectId(post_id)})
    except:
        return jsonify({'error': 'Invalid post ID format'}), 400
    
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    
    return jsonify(serialize_doc(post)), 200

@app.route('/api/posts/<post_id>', methods=['PUT'])
@require_admin
def update_post(post_id):
    """Update a post (admin only)"""
    try:
        post = posts.find_one({'_id': ObjectId(post_id)})
    except:
        return jsonify({'error': 'Invalid post ID format'}), 400
    
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    
    if not verify_blog_ownership(request.admin['_id'], post['blog_id']):
        return jsonify({'error': 'Unauthorized - you do not own this blog'}), 403
    
    data = request.json
    update_fields = {}
    
    if 'title' in data:
        update_fields['title'] = data['title']
    if 'excerpt' in data:
        update_fields['excerpt'] = data['excerpt']
    if 'content' in data:
        update_fields['content'] = data['content']
    if 'image' in data:
        update_fields['image'] = data['image']
    if 'category' in data:
        # Validate category
        blog = blogs.find_one({'_id': post['blog_id']})
        if data['category'] and data['category'] not in blog.get('categories', []):
            return jsonify({'error': f'Invalid category. Must be one of: {", ".join(blog.get("categories", []))}'}), 400
        update_fields['category'] = data['category']
    
    if not update_fields:
        return jsonify({'error': 'No fields to update'}), 400
    
    update_fields['updated_at'] = datetime.utcnow()
    
    posts.update_one(
        {'_id': ObjectId(post_id)},
        {'$set': update_fields}
    )
    
    return jsonify({'message': 'Post updated successfully'}), 200

@app.route('/api/posts/<post_id>', methods=['DELETE'])
@require_admin
def delete_post(post_id):
    """Delete a post (admin only)"""
    try:
        post = posts.find_one({'_id': ObjectId(post_id)})
    except:
        return jsonify({'error': 'Invalid post ID format'}), 400
    
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    
    if not verify_blog_ownership(request.admin['_id'], post['blog_id']):
        return jsonify({'error': 'Unauthorized - you do not own this blog'}), 403
    
    posts.delete_one({'_id': ObjectId(post_id)})
    comments.delete_many({'post_id': ObjectId(post_id)})
    
    return jsonify({'message': 'Post and associated comments deleted'}), 200

# ===== LIKES =====

@app.route('/api/posts/<post_id>/like', methods=['POST'])
def like_post(post_id):
    """Like a post (public, anonymous)"""
    try:
        result = posts.update_one(
            {'_id': ObjectId(post_id)},
            {'$inc': {'likes': 1}}
        )
    except:
        return jsonify({'error': 'Invalid post ID format'}), 400
    
    if result.matched_count == 0:
        return jsonify({'error': 'Post not found'}), 404
    
    post = posts.find_one({'_id': ObjectId(post_id)})
    return jsonify({'likes': post['likes']}), 200

# ===== COMMENTS =====

@app.route('/api/posts/<post_id>/comments', methods=['POST'])
def create_comment(post_id):
    """Create a comment (public, anonymous)"""
    data = request.json
    
    # Validation
    if not data.get('content'):
        return jsonify({'error': 'Comment content is required'}), 400
    
    if len(data.get('content', '')) > 1000:
        return jsonify({'error': 'Comment too long (max 1000 characters)'}), 400
    
    try:
        post = posts.find_one({'_id': ObjectId(post_id)})
    except:
        return jsonify({'error': 'Invalid post ID format'}), 400
    
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    
    comment_doc = {
        'post_id': ObjectId(post_id),
        'blog_id': post['blog_id'],
        'name': data.get('name', 'Anonymous'),
        'content': data.get('content'),
        'created_at': datetime.utcnow()
    }
    
    result = comments.insert_one(comment_doc)
    comment_doc['_id'] = str(result.inserted_id)
    
    return jsonify({
        'message': 'Comment added successfully',
        'comment': serialize_doc(comment_doc)
    }), 201

@app.route('/api/posts/<post_id>/comments', methods=['GET'])
def get_comments(post_id):
    """Get all comments for a post (public)"""
    try:
        comment_list = list(comments.find(
            {'post_id': ObjectId(post_id)}
        ).sort('created_at', -1))
    except:
        return jsonify({'error': 'Invalid post ID format'}), 400
    
    return jsonify({
        'comments': [serialize_doc(c) for c in comment_list]
    }), 200

@app.route('/api/comments/<comment_id>', methods=['DELETE'])
@require_admin
def delete_comment(comment_id):
    """Delete a comment (admin only)"""
    try:
        comment = comments.find_one({'_id': ObjectId(comment_id)})
    except:
        return jsonify({'error': 'Invalid comment ID format'}), 400
    
    if not comment:
        return jsonify({'error': 'Comment not found'}), 404
    
    if not verify_blog_ownership(request.admin['_id'], comment['blog_id']):
        return jsonify({'error': 'Unauthorized - you do not own this blog'}), 403
    
    comments.delete_one({'_id': ObjectId(comment_id)})
    
    return jsonify({'message': 'Comment deleted successfully'}), 200

# ===== HEALTH CHECK =====

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}), 200

if __name__ == '__main__':
    # Create indexes for better performance
    posts.create_index([('blog_id', 1), ('created_at', -1)])
    posts.create_index([('blog_id', 1), ('category', 1), ('created_at', -1)])
    comments.create_index([('post_id', 1), ('created_at', -1)])
    
    app.run(debug=True, host='0.0.0.0', port=5000)