import bcrypt from 'bcrypt' ;
import User from '../models/User.js';
import jwt from  'jsonwebtoken'; 
import crypto from 'crypto';
import Session from '../models/Session.js';

const ACCESS_TOKEN_TTL = '30m';  // thuongwf la duoi 15m 
const REFRESH_TOKEN_TTL = 14 * 24 * 60 * 60 *1000 ;  // 14 ngay 

export const signUp = async (req , res) => {
    try {
        const {username , password , email , firstName , lastName} = req.body ; 

        if(!username || !password || !email || !firstName || !lastName) {
            return res
            .status(400)
            .json({
                message: 
                "Khong the thieu username , password , email , firstName , vaf lastName"
            }); 
        }

        // kieemr tra username da ton tai chua 
        const duplicate = await User.findOne({username}) ; 

        if (duplicate) {
            return res.status(409).json({message : " username da ton tai "}) ; 


        }

        // ma hoa password 
        const hashedPassword = await bcrypt.hash(password , 10) ; // salt = 10 

        // taoj user moi 
        await User.create({
            username , 
            hashedPassword,
            email,
            displayName : `${firstName} ${lastName}`
        }) ; 

        // return 
        return res.sendStatus(204) ; 


    } catch (error) {
        console.error('loi khi goi signUp' , error) ; 
        return res.status(500).json({messege : "Loi he thong "}) ; 

    }
};

export const signIn = async( req , res)  => {
    try {
        // lay inputss
        const {username , password} = req.body ; 

        if(!username || !password) {
            return res.status(400).json({message : " thieeus username hoac password"}) ; 
        }

        // lay hashedPassword trong db de so voi password trong input 
        const user = await User.findOne({username}) ; 

        if( !user) {
            return res.status(401).json({message : ' username hoac password khong chinh xac'}); 

        }
        // kiem tra password 
        const passwordCorrect = await bcrypt.compare(password , user.hashedPassword) ; 

        if(!passwordCorrect) {
            return res
            .status(401) 
            .json({message : "username hoac password khong chinh xac "}) ;
        }

        // neu khip tao accessToken voi JWT 
        const accessToken =  jwt.sign(
            {userId : user._id }, 
            process.env.ACCESS_TOKEN_SECRET, 
            {expiresIn : ACCESS_TOKEN_TTL}
        ); 
        // tao refresh token 
        const  refreshToken = crypto.randomBytes(64).toString("hex") ; 

        // tao session moi de luu refresh token 
        await Session.create({
            userId : user._id , 
            refreshToken , 
            expiresAt : new Date(Date.now() + REFRESH_TOKEN_TTL),
        }) ; 

        // tra refrsh token ve torng cookie 
        res.cookie('refreshToken' , refreshToken , {
            httpOnly : true , 
            secure : true , 
            sameSite : 'none' , // backend , frontend deploy rieng 
            maxAge : REFRESH_TOKEN_TTL,
        }) ; 

        //tra access token ve trong res
        return res.status(200).json({message : ` User ${user.displayName} da logged in `, accessToken}  ) ;

    } catch (error)  {
        console.error(" loi khi goi signin " , error) ; 
        return res.status(500).json({ message : " loi he thong"}); 
    }
} ; 

export const signOut = async(req , res) => {
    try {
        // lay refresh token tu coookie 
        const token = req.cookies?.refreshToken ; 

        if(token) {
            // xoa refresh token trong access 
            await Session.deleteOne({refreshToken : token}) ; 

            // xoa cookie 
            res.clearCookie("refreshToken") ; 
        }

        return res.sendStatus(204) ; 
        
    }
    catch (error) {
        console.error("loi khi goi signout " , error) ;
        return res.status(500).json({messeage : "loi he thong "}) ; 
    }
};

export const refreshToken = async (req , res) => {
    try {
        // lay refresh token tu cookie 
        const token = req.cookies?.refreshToken ; 
        if(!token) {
            return res.status(401).json({message : "Token khong ton tai "}); 
        }
        // so voi refresh token trong db 
        const session = await Session.findOne({refreshToken : token }); 

        if(!session) {
            return res.status(403).json({message : " token khong hop le hoac da het han "}); 
        }
        // kiem tra het han chua 
        if (session.expiresAt < new Date()) {
            return res.status(403).json({message : "token da het han "}); 
        }

        // tao access token moi 
        const accessToken = jwt.sign({
            userId : session.userId 
        } , 
        process.env.ACCESS_TOKEN_SECRET , 
        {expiresIn : ACCESS_TOKEN_TTL}); 

        // return 
        return res.status(200).json({accessToken}); 

    } catch (error) {
        console.error("loi khi goi refreshToken", error) ; 
        return res.status(500).json({message : "Loi he thong"}); 
    }
}; 