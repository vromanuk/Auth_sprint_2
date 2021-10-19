from flask_restful import Resource


class Smoke(Resource):
    def get(self):
        """
        Server health check
        ---
        tags:
          - smoke
        responses:
          200:
            description: health check
            schema:
              properties:
                message:
                  type: string
        """
        return {"message": "OK"}
