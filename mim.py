from user import User

class ManInTheMiddle(User):
    def __init__(self):
        super().__init__('Mallory')
        self.secret_key_dict = {}  # To store secret keys for each user
        self.other_user_pub_key_dict = {}  # To store public keys for each user

    def receive_pub_key(self, other_user_pub_key, other_user_name):
        super().receive_pub_key(other_user_pub_key)
        self.other_user_pub_key_dict[other_user_name] = other_user_pub_key
        self.other_user_pub_key = None  # Clear the main other_user_pub_key to avoid confusion
    
    def secret_key(self, q, other_user_name):
        self.other_user_pub_key = self.other_user_pub_key_dict[other_user_name]
        super().secret_key(q)
        self.secret_key_dict[other_user_name] = self.secret
        self.other_user_pub_key = None  # Clear the main other_user_pub_key to avoid confusion
        self.secret = None  # Clear the main secret to avoid confusion, questionable implementation but works for use case