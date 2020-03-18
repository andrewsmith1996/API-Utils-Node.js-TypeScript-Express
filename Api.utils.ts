import axios, { AxiosResponse } from 'axios';
import { ApiResponse } from '../models/responses/ApiResponse';
const jwt = require('jsonwebtoken');

export interface APIData {
  status: number,
  data: any;
}

class ApiResponse<T> {
  public payload: T;
  public errorMessage: string;
  public errorCode: number;
  
  constructor(payload: T = null, errorMessage = '', errorCode = 0) {
    this.payload = payload as T;
    this.errorMessage = errorMessage;
    this.errorCode = errorCode;
  }
}

export class APIUtils {

  /**
   * Generic GET method, takes a generic type T and maps the response to this type.
   * @param {string} url the URL we'll be calling
   * @memberof APIUtils
   * @returns {T} the return data, mapped to the type T.
   */
  public static async get<T>(url: string): Promise<APIData> { 
    const response: AxiosResponse = await axios.get(url, { auth: {
      username: process.env.USERNAME,
      password: process.env.PASSWORD
    }});
    return { status: response.status, data: response.data as T } as APIData;
  }

  /**
   * Generic POST method, takes a generic type T and maps the response to this type.
   * @param {string} url the URL we'll be posting to
   * @param {U} body the post body we'll be using.
   * @memberof APIUtils
   * @returns {T} the return data, mapped to the type T.
   */
  public static async post<U, T>(url: string, body: U): Promise<APIData> { 
    const response: AxiosResponse = await axios.post(url, body, { auth: {
      username: process.env.USERNAME,
      password: process.env.PASSWORD
    }});
    return { status: response.status, data: response.data as T } as APIData;
  }

  /**
   * Generic PUT method, takes a generic type T and maps the response to this type.
   * @param {string} url the URL we'll be 'putting' to
   * @param {U} body the post body we'll be using.
   * @memberof APIUtils
   * @returns {T} the return data, mapped to the type T.
   */
  public static async put<U, T>(url: string, body: U): Promise<APIData> { 
    const response: AxiosResponse = await axios.put(url, body, { auth: {
      username: process.env.USERNAME,
      password: process.env.PASSWORD
    }});
    return { status: response.status, data: response.data as T } as APIData;
  }

  /**
   * Validates a JWT token
   * @memberof APIUtils
   */
  public static validateToken(req, res, next) : void {
    const authorizationHeader = req.headers.authorization;    
    if (authorizationHeader) {
      const token: string = authorizationHeader.split(' ')[1];
      const options = { issuer: process.env.JWT_ISSUER } as { issuer: string };
      try {
        req.decoded = jwt.verify(token, process.env.JWT_SECRET, options);;
        next(); // Call next to pass execution to the NEXT middleware.
      } catch (err) {
        res.status(401).send(new ApiResponse(null, 'Invalid Authentication error', 1));
      }
    } else res.status(401).send(new ApiResponse(null, 'Invalid Authentication error', 1));
  }
