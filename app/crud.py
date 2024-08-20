from sqlalchemy.orm import Session
from fastapi import HTTPException

from . import models, schemas, auth

def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()


def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def get_items(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Item).offset(skip).limit(limit).all()


def create_user_item(db: Session, item: schemas.ItemCreate, user_id: int):
    db_item = models.Item(**item.dict(), owner_id=user_id)
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item

def get_user_items(db: Session, user_id: int, skip: int = 0, limit: int = 100):
    return (
        db.query(models.Item)
        .filter(models.Item.owner_id == user_id)  
        .offset(skip)
        .limit(limit)
        .all()
    )

def delete_user_item(db: Session, user_id: int, item_id: int):
    item = db.query(models.Item).filter(models.Item.id == item_id, models.Item.owner_id == user_id).first()
    
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found or does not belong to the user")

    db.delete(item)
    db.commit()

    return {"detail": f"Item {item_id} deleted successfully"}

def put_user_item(db: Session, user_id: int, item_id: int, item_data: schemas.ItemUpdate):
    item = db.query(models.Item).filter(models.Item.id == item_id, models.Item.owner_id == user_id).first()
    
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found or does not belong to the user")
    
    for key, value in item_data.dict(exclude_unset=True).items():
        setattr(item, key, value)

    # Сохраняем изменения в базе данных
    db.commit()
    db.refresh(item)
    
    return item