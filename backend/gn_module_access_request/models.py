from geonature.utils.env import DB

class Request(DB.Model):
    __tablename__ = "t_request"
    __table_args__ = {"schema": "gn_access_requests"}
