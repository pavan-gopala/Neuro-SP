class TokenValidator:
    def isValid(self, token):
        if len(token) < 20:
            return False
        return True