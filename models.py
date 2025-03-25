from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    id: int = Field(primary_key=True)
    name: str = Field(max_length=64, index=True)
    password: str = Field(max_length=64)