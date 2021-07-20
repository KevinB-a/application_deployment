import sys

sys.path.insert(0, "/home/apprenant/simplon_project/application_deployment/")

from utils.functions import *

import pickle

from utils.classes import *

app = FastAPI()

@app.get("/{input}")
def predict(input: str, current_user: User = Depends(get_current_active_user)):

    tfidf, model = pickle.load(open('model.bin', 'rb'))
    predictions = model.predict(tfidf.transform([input]))
    label = predictions[0]
    return {'text': input, 'label': label , 'owner': current_user.username}


@app.post("/token", response_model=Token)

async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):

    user = authenticate_user(fake_users_db, form_data.username, form_data.password)

    if not user:

        raise HTTPException(

            status_code=status.HTTP_401_UNAUTHORIZED,

            detail="Incorrect username or password",

            headers={"WWW-Authenticate": "Bearer"},

        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    access_token = create_access_token(

        data={"sub": user.username}, expires_delta=access_token_expires
                                      )

    return {"access_token": access_token, "token_type": "bearer"}



@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": "Foo", "owner": current_user.username}]