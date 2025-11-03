import User from '../models/usersSchema.js';
import PasswordReset from '../models/passwordResetSchema.js';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { sendPasswordResetEmail, sendPasswordChangedEmail } from '../config/nodemailer.config.js';

/**
 * @module PasswordController
 * este controlador gestiona la recuperación, restablecimiento y verificación de contraseñas
 */

/**
 * sirve para solicitar la recuperación de contraseña para un usuario registrado
 * 
 * @async
 * @function forgotPassword
 * @param {Object} req - objeto de solicitud HTTP (req)
 * @param {Object} res - objeto de respuesta HTTP (res)
 * @property {string} req.body.email - email del usuario que solicita restablecer su contraseña
 * 
 * @returns {Promise<void>} envía una respuesta JSON que indica el resultado del proces
 * 
 * @throws {Error} error interno del servidor si ocurre una excepción
 * 
 * @example
 * // ejemplo:
 * POST /api/auth/forgot-password
 * Body: { "email": "usuario@correo.com" }
 */
export const forgotPassword = async(req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ mensaje: 'El email es requerido' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(200).json({
                mensaje: 'Si el email existe, recibirás un correo con las instrucciones para restablecer tu contraseña'
            });
        }

        await PasswordReset.deleteMany({ userId: user._id });

        const resetToken = crypto.randomBytes(32).toString('hex');
        const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

        await PasswordReset.create({
            userId: user._id,
            token: hashedToken
        });

        try {
            await sendPasswordResetEmail(user.email, resetToken, user.username);
            res.status(200).json({
                mensaje: 'Si el email existe, recibirás un correo con las instrucciones para restablecer tu contraseña'
            });
        } catch (emailError) {
            console.error('Error al enviar email:', emailError);
            await PasswordReset.deleteOne({ userId: user._id, token: hashedToken });
            return res.status(500).json({
                mensaje: 'Error al enviar el correo de recuperación. Por favor, intenta de nuevo más tarde.'
            });
        }

    } catch (error) {
        console.error('Error en forgotPassword:', error);
        res.status(500).json({ mensaje: 'Error interno del servidor al procesar la solicitud' });
    }
};

/**
 * permite restablecer la contraseña de un usuario a partir de un token válido
 * 
 * @async
 * @function resetPassword
 * @param {Object} req - Request.
 * @param {Object} res - Response.
 * @property {string} req.body.token - token único enviado al correo del usuario
 * @property {string} req.body.newPassword - nueva contraseña 
 * 
 * @returns {Promise<void>} envía una respuesta JSON indicando el resultado del proceso
 * 
 * @throws {Error} ei el token es inválido, expirado o el usuario no existe
 * 
 * @example
 * // Ejemplo:
 * POST /api/auth/reset-password
 * Body: { "token": "abc123", "newPassword": "MiNuevaPass123" }
 */
export const resetPassword = async(req, res) => {
    try {
        const { token, newPassword } = req.body;

        if (!token || !newPassword) {
            return res.status(400).json({ mensaje: 'Token y nueva contraseña son requeridos' });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ mensaje: 'La contraseña debe tener al menos 6 caracteres' });
        }

        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
        const resetToken = await PasswordReset.findOne({ token: hashedToken });

        if (!resetToken) {
            return res.status(400).json({ mensaje: 'Token inválido o expirado' });
        }

        const user = await User.findById(resetToken.userId);
        if (!user) {
            return res.status(404).json({ mensaje: 'Usuario no encontrado' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        user.password = hashedPassword;
        await user.save();

        await PasswordReset.deleteOne({ _id: resetToken._id });

        try {
            await sendPasswordChangedEmail(user.email, user.username);
        } catch (emailError) {
            console.error('Error al enviar email de confirmación:', emailError);
        }

        res.status(200).json({ mensaje: 'Contraseña actualizada exitosamente' });

    } catch (error) {
        console.error('Error en resetPassword:', error);
        res.status(500).json({ mensaje: 'Error interno del servidor al restablecer la contraseña' });
    }
};

/**
 * verifica si un token de recuperación es válido
 * 
 * @async
 * @function verifyResetToken
 * @param {Object} req - Request
 * @param {Object} res - Response
 * @property {string} req.params.token - token enviado para verificación
 * 
 * @returns {Promise<void>} devuelve si el token es válido y el correo asociado
 * 
 * @example
 * // Ejemplo:
 * GET /api/auth/verify-reset-token/:token
 */
export const verifyResetToken = async(req, res) => {
    try {
        const { token } = req.params;

        if (!token) {
            return res.status(400).json({ mensaje: 'Token es requerido' });
        }

        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
        const resetToken = await PasswordReset.findOne({ token: hashedToken });

        if (!resetToken) {
            return res.status(400).json({
                valid: false,
                mensaje: 'Token inválido o expirado'
            });
        }

        const user = await User.findById(resetToken.userId);
        if (!user) {
            return res.status(404).json({
                valid: false,
                mensaje: 'Usuario no encontrado'
            });
        }

        res.status(200).json({
            valid: true,
            mensaje: 'Token válido',
            email: user.email
        });

    } catch (error) {
        console.error('Error en verifyResetToken:', error);
        res.status(500).json({ mensaje: 'Error interno del servidor al verificar el token' });
    }
};