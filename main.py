from flask import Flask, render_template, redirect, request, jsonify
from google.cloud import datastore
import requests
import random
import string
from datetime import datetime

import json
from os import environ as env
from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for
from urllib.request import urlopen
from jose import jwt

ALGORITHMS = ["RS256"]
USERS = 'users'
POSTS = 'posts'
COLLECTIONS = 'collections'

client = datastore.Client()

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header


def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                         "description":
                         "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://" + env.get("AUTH0_DOMAIN") +
                      "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=env.get("AUTH0_CLIENT_ID"),
                issuer="https://" + env.get("AUTH0_DOMAIN")+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                         "description":
                         "No RSA key in JWKS"}, 401)

# Decode the JWT supplied in the Authorization header

@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token

    new_user = datastore.entity.Entity(key=client.key(USERS))
    new_user.update({"name": session["user"]["userinfo"]["name"], "userId": session["user"]["userinfo"]["sub"],
                     "email":  session["user"]["userinfo"]["email"], "creationDate": datetime.now().strftime("%Y-%m-%d"),
                     "collections": [], "posts": []
                     })
    client.put(new_user)

    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

### CRUD Routes

@app.route("/")
def home():
    return render_template("home.html", session=session.get('user'), pretty=json.dumps(session.get('user'), indent=4))


@app.route("/users", methods=['GET'])
def getUsers():
    query = client.query(kind=USERS)
    results = list(query.fetch())
    for entity in results:
        entity["id"] = entity.key.id
    output = {"numberOfUsers" : len(results), "users": results}
    return (output, 200)


@app.route('/posts', methods=['POST', 'GET'])
def posts_get_post():
    accept_header = request.headers.get('Accept', '')
    if 'application/json' not in accept_header and '*/*' not in accept_header:
        return {'Error': 'Client must accept JSON'}, 406
    elif request.method == 'POST':
        payload = verify_jwt(request)
        content = request.get_json()
        new_post = datastore.entity.Entity(key=client.key(POSTS))
        new_post.update({"title": content["title"], "content": content["content"], "creationDate": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                         "collections": [], "author": payload['sub']})
        client.put(new_post)

        # Add post to User
        query = client.query(kind=USERS)
        jwt_sub = payload['sub']
        query.add_filter("userId", "=", jwt_sub)
        results = list(query.fetch())
        results[0]["posts"].append(new_post.key.id)
        client.put(results[0])

        return {
            'id': new_post.key.id,
            'title': new_post['title'],
            'content': new_post['content'],
            'creationDate': new_post['creationDate'],
            'collections': new_post['collections'],
            'self': request.url + '/' + str(new_post.key.id)
        }, 201
    elif request.method == 'GET':
        payload = verify_jwt(request)
        jwt_sub = payload['sub']

        # Count total number of posts
        total_posts_query = client.query(kind=POSTS)
        total_posts_query.add_filter("author", "=", jwt_sub)
        total_posts_count = len(list(total_posts_query.fetch()))

        query = client.query(kind=POSTS)
        query.add_filter("author", "=", jwt_sub)

        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        b_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = b_iterator.pages
        results = list(next(pages))
        if b_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None

        for entity in results:
            entity["id"] = entity.key.id
            entity["self"] = request.url + '/' + str(entity.key.id)

        output = {"totalNumberOfItems":total_posts_count, "posts":results}
        if next_url:
            output["next"] = next_url
        return (output, 200)
    else:
        return {'Error': 'Method not recogonized'}, 405


@app.route('/posts/<post_id>', methods=['GET', 'DELETE', 'PUT', 'PATCH'])
def post_id_get(post_id):
    accept_header = request.headers.get('Accept', '')
    if request.method != 'DELETE' and 'application/json' not in accept_header and '*/*' not in accept_header:
        return {'Error': 'Client must accept JSON'}, 406
    payload = verify_jwt(request)
    jwt_sub = payload['sub']
    post_key = client.key(POSTS, int(post_id))
    post = client.get(key=post_key)
    if post == None:
        return (jsonify({'Error': 'Invalid Post ID'}), 404)
    elif post['author'] != jwt_sub:
        return (jsonify({'Error': 'This post does not belong to you'}), 403)
    
    if request.method == 'GET':
        post['id'] = post.key.id
        post['self'] = request.url
        return post, 200
    if request.method == 'DELETE':
        # Delete from user's posts
        query = client.query(kind=USERS)
        jwt_sub = payload['sub']
        query.add_filter("userId", "=", jwt_sub)
        results = list(query.fetch())
        post_id = int(post_id)
        if post_id in results[0]["posts"]:
            results[0]["posts"].remove(post_id)
        client.put(results[0])

        #Delete post from its collections
        for coll in post['collections']:
            collection_key = client.key(COLLECTIONS, int(coll))
            collection = client.get(key=collection_key)
            collection['posts'].remove(post.key.id)
            client.put(collection)

        client.delete(post_key)
        return ('',204)
    if request.method == 'PUT':
        content = request.get_json()
        post.update({"title": content["title"], "content": content["content"]})
        client.put(post)
        print(content)
        return {
            'id': post.key.id,
            'title': post['title'],
            'content': post['content'],
            'creationDate': post['creationDate'],
            'collections': post['collections'],
            'self': request.url
        }, 200
    if request.method == 'PATCH':
        content = request.get_json()
        if 'title' in content:
            post['title'] = content['title']
        if 'content' in content:
            post['content'] = content['content']
        client.put(post)
        return {
            'id': post.key.id,
            'title': post['title'],
            'content': post['content'],
            'creationDate': post['creationDate'],
            'collections': post['collections'],
            'self': request.url
        }, 200


@app.route('/collections', methods=['POST', 'GET'])
def collections_get_post():
    if request.method == 'POST':
        payload = verify_jwt(request)
        content = request.get_json()
        new_collection = datastore.entity.Entity(key=client.key(COLLECTIONS))
        new_collection.update({"name": content["name"], "description": content["description"], "creationDate": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                               "posts": [], "owner": payload['sub']})
        client.put(new_collection)

        # Add collection to User
        query = client.query(kind=USERS)
        jwt_sub = payload['sub']
        query.add_filter("userId", "=", jwt_sub)
        results = list(query.fetch())
        results[0]["collections"].append(new_collection.key.id)
        client.put(results[0])

        return {
            'id': new_collection.key.id,
            'name': new_collection['name'],
            'description': new_collection['description'],
            'creationDate': new_collection['creationDate'],
            'posts': new_collection['posts'],
            'owner': new_collection['owner'],
            'self': request.url + '/' + str(new_collection.key.id)
        }, 201
    if request.method == 'GET':
        payload = verify_jwt(request)
        jwt_sub = payload['sub']

        # Count total number of collections
        total_collections_query = client.query(kind=COLLECTIONS)
        total_collections_query.add_filter("owner", "=", jwt_sub)
        total_collections_count = len(list(total_collections_query.fetch()))

        query = client.query(kind=COLLECTIONS)
        query.add_filter("owner", "=", jwt_sub)

        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        b_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = b_iterator.pages
        results = list(next(pages))
        if b_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None

        for entity in results:
            entity["id"] = entity.key.id
            entity["self"] = request.url + '/' + str(entity.key.id)

        output = {"totalNumberOfItems":total_collections_count, "collections":results}
        if next_url:
            output["next"] = next_url
        return (output, 200)


@app.route('/collections/<collection_id>', methods=['GET', 'DELETE', 'PUT', 'PATCH'])
def collection_id_get(collection_id):
    payload = verify_jwt(request)
    jwt_sub = payload['sub']

    collection_key = client.key(COLLECTIONS, int(collection_id))
    collection = client.get(key=collection_key)
    if collection == None:
        return (jsonify({'Error': 'Invalid Collection ID'}), 404)
    elif collection['owner'] != jwt_sub:
        return (jsonify({'Error': 'This collection does not belong to you'}), 403)
    
    if request.method == 'GET':
        collection['id'] = collection.key.id
        collection['self'] = request.url
        return collection, 200
    
    if request.method == 'DELETE':
        # Delete from user's collections
        query = client.query(kind=USERS)
        jwt_sub = payload['sub']
        query.add_filter("userId", "=", jwt_sub)
        results = list(query.fetch())
        collection_id = int(collection_id)
        if collection_id in results[0]["collections"]:
            results[0]["collections"].remove(collection_id)
        client.put(results[0])

        #Delete collections from its posts
        for p in collection['posts']:
            post_key = client.key(POSTS, int(p))
            post = client.get(key=post_key)
            post['collections'].remove(collection.key.id)
            client.put(post)

        client.delete(collection_key)
        return ('',204)
    if request.method == 'PUT':
        content = request.get_json()
        collection.update({"name": content["name"], "description": content["description"]})
        client.put(collection)
        return {
            'id': collection.key.id,
            'name': collection['name'],
            'description': collection['description'],
            'creationDate': collection['creationDate'],
            'posts': collection['posts'],
            'owner': collection['owner'],
            'self': request.url
        }, 200
    if request.method == 'PATCH':
        content = request.get_json()
        if 'name' in content:
            collection['name'] = content['name']
        if 'description' in content:
            collection['description'] = content['description']
        client.put(collection)
        return {
            'id': collection.key.id,
            'name': collection['name'],
            'description': collection['description'],
            'creationDate': collection['creationDate'],
            'posts': collection['posts'],
            'owner': collection['owner'],
            'self': request.url
        }, 200

@app.route('/collections/<collection_id>/posts/<post_id>', methods=['DELETE', 'PUT'])
def add_remove_collection_post(collection_id, post_id):
    #unprotected
    collection_key = client.key(COLLECTIONS, int(collection_id))
    collection = client.get(key=collection_key)
    post_key = client.key(POSTS, int(post_id))
    post = client.get(key=post_key)
    if collection == None:
        return (jsonify({'Error': 'Invalid Collection ID'}), 404)
    if post == None:
        return (jsonify({'Error': 'Invalid Post ID'}), 404)
    
    if request.method == 'PUT':
        if post.key.id in collection['posts']:
            return {"Error":"This post is already in this collection"}, 403
        collection['posts'].append(post.key.id)
        post['collections'].append(collection.key.id)
        client.put(collection)
        client.put(post)

        return ('', 204)
    
    if request.method == 'DELETE':
        if post.key.id not in collection['posts'] or collection.key.id not in post['collections']:
            return {"Error":"Post not in collection"}, 403
        collection['posts'].remove(post.key.id)
        post['collections'].remove(collection.key.id)
        client.put(collection)
        client.put(post)
        return ('', 204)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
