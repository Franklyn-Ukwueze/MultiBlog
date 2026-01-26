from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime
import os
from functools import wraps

app = Flask(__name__)
CORS(app)

# MongoDB connection
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
client = MongoClient(MONGO_URI)
db = client['multi_blog_db']

# Collections
blogs = db['blogs']
posts = db['posts']
comments = db['comments']

# Simple auth decorator
def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid authorization'}), 401
        
        token = auth_header.split(' ')[1]
        blog_id = request.view_args.get('blog_id') or request.json.get('blog_id')
        
        blog = blogs.find_one({'_id': ObjectId(blog_id)})
        if not blog or blog.get('admin_token') != token:
            return jsonify({'error': 'Unauthorized'}), 403
        
        return f(*args, **kwargs)
    return decorated

# Helper to serialize MongoDB documents
def serialize_doc(doc):
    if doc:
        doc['_id'] = str(doc['_id'])
        if 'blog_id' in doc:
            doc['blog_id'] = str(doc['blog_id'])
        if 'post_id' in doc:
            doc['post_id'] = str(doc['post_id'])
    return doc

# ===== BLOG MANAGEMENT =====

@app.route('/api/blogs', methods=['POST'])
def create_blog():
    """Create a new blog (generates admin token)"""
    data = request.json
    
    blog_doc = {
        'name': data.get('name'),
        'description': data.get('description', ''),
        'admin_token': os.urandom(32).hex(),
        'created_at': datetime.utcnow()
    }
    
    result = blogs.insert_one(blog_doc)
    blog_doc['_id'] = str(result.inserted_id)
    
    return jsonify({
        'message': 'Blog created successfully',
        'blog_id': blog_doc['_id'],
        'admin_token': blog_doc['admin_token'],
        'warning': 'Save this admin token! You need it to manage this blog.'
    }), 201

@app.route('/api/blogs/<blog_id>', methods=['GET'])
def get_blog(blog_id):
    """Get blog details (public)"""
    blog = blogs.find_one({'_id': ObjectId(blog_id)})
    if not blog:
        return jsonify({'error': 'Blog not found'}), 404
    
    # Don't expose admin token
    blog.pop('admin_token', None)
    return jsonify(serialize_doc(blog))

# ===== POST MANAGEMENT =====

@app.route('/api/blogs/<blog_id>/posts', methods=['POST'])
@require_admin
def create_post(blog_id):
    """Create a new post (admin only)"""
    data = request.json
    
    post_doc = {
        'blog_id': ObjectId(blog_id),
        'title': data.get('title'),
        'excerpt': data.get('excerpt', ''),
        'content': data.get('content'),
        'author': data.get('author', 'Admin'),
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
    """Get all posts for a blog (public)"""
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 10))
    skip = (page - 1) * limit
    
    post_list = list(posts.find(
        {'blog_id': ObjectId(blog_id)}
    ).sort('created_at', -1).skip(skip).limit(limit))
    
    total = posts.count_documents({'blog_id': ObjectId(blog_id)})
    
    return jsonify({
        'posts': [serialize_doc(p) for p in post_list],
        'total': total,
        'page': page,
        'pages': (total + limit - 1) // limit
    })

@app.route('/api/posts/<post_id>', methods=['GET'])
def get_post(post_id):
    """Get a single post (public)"""
    post = posts.find_one({'_id': ObjectId(post_id)})
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    
    return jsonify(serialize_doc(post))

@app.route('/api/posts/<post_id>', methods=['PUT'])
@require_admin
def update_post(post_id):
    """Update a post (admin only)"""
    data = request.json
    post = posts.find_one({'_id': ObjectId(post_id)})
    
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    
    update_fields = {}
    if 'title' in data:
        update_fields['title'] = data['title']
    if 'excerpt' in data:
        update_fields['excerpt'] = data['excerpt']
    if 'content' in data:
        update_fields['content'] = data['content']
    
    update_fields['updated_at'] = datetime.utcnow()
    
    posts.update_one(
        {'_id': ObjectId(post_id)},
        {'$set': update_fields}
    )
    
    return jsonify({'message': 'Post updated successfully'})

@app.route('/api/posts/<post_id>', methods=['DELETE'])
@require_admin
def delete_post(post_id):
    """Delete a post (admin only)"""
    result = posts.delete_one({'_id': ObjectId(post_id)})
    
    if result.deleted_count == 0:
        return jsonify({'error': 'Post not found'}), 404
    
    # Also delete all comments for this post
    comments.delete_many({'post_id': ObjectId(post_id)})
    
    return jsonify({'message': 'Post and associated comments deleted'})

# ===== LIKES =====

@app.route('/api/posts/<post_id>/like', methods=['POST'])
def like_post(post_id):
    """Like a post (public, anonymous)"""
    result = posts.update_one(
        {'_id': ObjectId(post_id)},
        {'$inc': {'likes': 1}}
    )
    
    if result.matched_count == 0:
        return jsonify({'error': 'Post not found'}), 404
    
    post = posts.find_one({'_id': ObjectId(post_id)})
    return jsonify({'likes': post['likes']})

# ===== COMMENTS =====

@app.route('/api/posts/<post_id>/comments', methods=['POST'])
def create_comment(post_id):
    """Create a comment (public, anonymous)"""
    data = request.json
    
    # Verify post exists
    post = posts.find_one({'_id': ObjectId(post_id)})
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
    comment_list = list(comments.find(
        {'post_id': ObjectId(post_id)}
    ).sort('created_at', -1))
    
    return jsonify({
        'comments': [serialize_doc(c) for c in comment_list]
    })

@app.route('/api/comments/<comment_id>', methods=['DELETE'])
@require_admin
def delete_comment(comment_id):
    """Delete a comment (admin only)"""
    result = comments.delete_one({'_id': ObjectId(comment_id)})
    
    if result.deleted_count == 0:
        return jsonify({'error': 'Comment not found'}), 404
    
    return jsonify({'message': 'Comment deleted successfully'})

# ===== HEALTH CHECK =====

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

if __name__ == '__main__':
    # Create indexes for better performance
    posts.create_index([('blog_id', 1), ('created_at', -1)])
    comments.create_index([('post_id', 1), ('created_at', -1)])
    
    app.run(debug=True, host='0.0.0.0', port=5000)