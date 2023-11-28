from fastapi import FastAPI, Depends, HTTPException, Path, status, Form, Security
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from jose import JWTError, jwt
from typing import List
from pydantic import BaseModel

app = FastAPI()

# Secret key to sign the JWT
SECRET_KEY = "secret"

# # Define the OAuth2 Password Bearer for token-based authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", scopes={"read": "Read-only access", "write": "Write access", "admin": "Admin access"})


# # Pydantic model for a user
class User(BaseModel):
    username: str
    email: str
    scopes: List[str]

# Mock user database (in-memory)
users_db = {
    "testuser": {
        "username": "testuser",
        "email": "testuser@example.com",
        "password": "password123",
        "scopes": ["read", "write"],
    },
    "adminuser": {
        "username": "adminuser",
        "email": "adminuser@example.com",
        "password": "adminpassword",
        "scopes": ["read", "write", "admin"],
    }
}

# # Function to create a JWT token
def create_jwt_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm="HS256")

# # Function to get the current user based on the JWT token
async def get_current_user(security_scopes: SecurityScopes, token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        scopes: List[str] = payload.get("scopes", [])
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
   
    user = User(username=username, email=f"{username}@example.com", scopes=scopes) 

    for scope in security_scopes.scopes:
        if scope not in user.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have access to this resource",
            )

    return user 

# Dependency for checking if the current user has required scopes
# def has_required_scopes(current_user: User = Security(get_current_user, scopes=["read"]) ):
#     if current_user == None:
#         raise HTTPException(
#             status_code=status.HTTP_403_FORBIDDEN,
#             detail="Invalid user",
#         )
#     return current_user

async def has_admin_access(current_user_scopes: User = Depends(get_current_user)):
    if "admin" not in current_user_scopes.scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have admin access",
        )

@app.get("/")
async def home():
    return  { "message": "Authorization" } 


# Registration endpoint
@app.post("/admin/register")
async def register(username: str = Form(...), email: str = Form(...), password: str = Form(...)):
    # In a real scenario, you would hash the password and store user data in a database
    users_db[username] = {"username": username, "email": email, "password": password, "scopes": ["read", "write", "admin"]}
    return {"message": "Admin registered successfully"}

@app.post("/register")
async def register(username: str = Form(...), email: str = Form(...), password: str = Form(...)):
    # In a real scenario, you would hash the password and store user data in a database
    users_db[username] = {"username": username, "email": email, "password": password, "scopes": ["read", "write"]}
    return {"message": "User registered successfully"}


# # Route to generate a JWT token (simulating the token endpoint)
@app.post("/token")
async def generate_token(username: str = Form(...), password: str = Form(...)):
    # In a real scenario, you would validate the credentials and issue a token
    user = users_db.get(username)
    if user and password == user["password"]:
        token_data = {"sub": username, "scopes": user["scopes"], "iss": "fastapi-oauth2"}
        return {"access_token": create_jwt_token(token_data), "token_type": "bearer"}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# # Protected route accessible to users with specific scopes
@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# # Protected route with required scopes
@app.get("/admin/dashboard", response_model=List[User])
async def admin_dashboard(current_user: User = Depends(has_admin_access)):
    return list(users_db.values()) 


# Updated routes for admin to update or delete any user
@app.put("/users/{username}", response_model=User)
async def update_user(  new_user_data: User, username: str = Path(..., title="The username of the user to update"), current_user: User = Depends(has_admin_access)):
    # In a real scenario, you would update the user's data in the database
    user_to_update = users_db.get(username)
    if user_to_update:
        user_to_update["username"] = new_user_data.username
        user_to_update["email"] = new_user_data.email
        return user_to_update
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

@app.delete("/users/{username}", response_model=dict)
async def delete_user(username: str = Path(..., title="The username of the user to delete"), current_user: User = Depends(has_admin_access)):
    # In a real scenario, you would delete the user's data from the database
    if username in users_db:
        del users_db[username]
        return {"message": "User deleted successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
