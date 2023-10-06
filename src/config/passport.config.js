import passport from "passport";
import LocalStrategy from 'passport-local'
import GithubStretegy from 'passport-github2'
import bcrypt from 'bcrypt'
import { userModel } from "../models/user.model.js";

const initializedPassport = () => {
    passport.use('register', new LocalStrategy({passReqToCallback: true , usernameField: 'email'} , async (req,username,password,done) => {
        const {first_name, last_name, age} = req.body
        try{
            const exist = await userModel.findOne({email: username})
            if(exist){
                return done(null, false)
            }

            const user = await userModel.create({first_name,last_name,age,email:username, password: bcrypt.hashSync(password, bcrypt.genSaltSync(10))})
            
            return done(null, user);
        } catch(error){
            return done(error)
        }
    }));

    passport.use('login', new LocalStrategy({ usernameField: 'email' }, async (username, password, done) => {
        try {
            const user = await userModel.findOne({ email: username })
            if (!user) {
                return done(null, false); // El usuario no existe
            }
    
            if (!bcrypt.compareSync(password, user.password)) {
                return done(null, false); // La contraseña es incorrecta
            }
    
            // Si llegamos aquí, la autenticación fue exitosa
            return done(null, user);
        } catch (error) {
            return done(error);
        }
    }));

    passport.use('github', new GithubStretegy({
        clientID: 'Iv1.28524b200f8a7660',
        clientSecret: 'd1617f2e14eb2f9317ae20aae0a8dae1cc910257' ,
        callbackURL: 'http://localhost:8080/api/githubcallback' ,
        scope:['user:email']
    } , async (accessToken, refreshToken, profile, done) => {
        try {
            const email = profile.email[0].value
        const user  =await userModel.findOne({email})

        if(!user) {
            const newUser = await userModel.create({
                first_name: profile._json.name,
                last_name: '',
                age: 18,
                password: '',
                email
            })

            return done(null, newUser )
        }

        return done(null, user)
        } catch (error) {
            return done(error)
        }
    }))

    passport.serializeUser((user, done) => {
        done(null, user._id)
    })

    passport.deserializeUser( async (id, done) => {
        const user = await userModel.findById(id)
        done(null,user)
    })
}

export default initializedPassport