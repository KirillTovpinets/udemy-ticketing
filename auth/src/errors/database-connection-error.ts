import { CustomError } from "./custom-error";

export class DatabaseConnectionError extends CustomError {
    reason = 'Faild to connect to database'
    statusCode = 500;
    constructor(){
        super('Error connecting to database');

        Object.setPrototypeOf(this, DatabaseConnectionError.prototype);
    }

    serializeErrors() {
        return [
            { message: this.reason }
        ]
    }
}