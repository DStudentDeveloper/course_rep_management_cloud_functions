/**
 * Import function triggers from their respective submodules:
 *
 * const {onCall} = require("firebase-functions/v2/https");
 * const {onDocumentWritten} = require("firebase-functions/v2/firestore");
 *
 * See a full list of supported triggers at https://firebase.google.com/docs/functions
 */

const {onCall, HttpsError} = require("firebase-functions/v2/https");
const logger = require("firebase-functions/logger");
const {initializeApp} = require("firebase-admin/app");
const {getAuth} = require("firebase-admin/auth");

initializeApp();
// https://firebase.google.com/docs/functions/get-started

const validateAuth = (auth, requireAdmin = false) => {
  if (!auth) {
    throw new HttpsError(
        "unauthenticated",
        "Request is not authenticated",
    );
  }

  if (requireAdmin && !auth.token.admin) {
    throw new HttpsError(
        "permission-denied",
        "Only admins can perform this operation.",
    );
  }
};

exports.makeAdmin = onCall(async (request, _) => {
  const {uid} = request.data;

  if (!uid) {
    throw new HttpsError(
        "invalid-argument",
        "Missing required parameter: uid.",
    );
  }

  try {
    const token = await getAuth().createCustomToken(uid, {admin: true});
    return {token};
  } catch (error) {
    logger.error("Error making user an admin.", error, {structuredData: true});

    throw new HttpsError("internal", "Error making user an admin.");
  }
});

exports.authenticateCourseRepresentative = onCall(async (request, _) => {
  validateAuth(request.auth, true);
  const {email, displayName} = request.data;

  if (!email || !displayName) {
    throw new HttpsError(
        "invalid-argument",
        "Missing required parameters: email, password or displayName.",
    );
  }

  try {
    const user = await getAuth().createUser({
      email: email,
      password: "Central@123",
      displayName: displayName,
    });

    return {uid: user.uid};
  } catch (error) {
    logger.error(
        "Error creating Firebase Auth user:",
        error,
        {structuredData: true},
    );
    throw new HttpsError(
        "internal",
        "Failed to create Firebase Auth user.",
    );
  }
});

exports.updateCourseRepresentativeAuth = onCall(async (request, _) => {
  validateAuth(request.auth, true);
  const {uid, displayName, email} = request.data;

  if (!uid) {
    throw new HttpsError(
        "invalid-argument",
        "Missing required parameter: uid",
    );
  }

  const updates = {};
  if (displayName) updates.displayName = displayName;
  if (email) updates.email = email;

  if (Object.keys(updates).length === 0) {
    throw new HttpsError(
        "invalid-argument",
        "No valid fields to update.",
    );
  }

  try {
    await getAuth().updateUser(uid, updates);
    return {message: "Firebase Auth user updated successfully."};
  } catch (error) {
    logger.error(
        "Error updating Firebase Auth user:",
        error,
        {structuredData: true},
    );
    throw new HttpsError(
        "internal",
        "Failed to update Firebase Auth user.",
    );
  }
});

exports.deleteCourseRepresentativeAuth = onCall(async (request, _) => {
  validateAuth(request.auth, true);
  const {uid} = request.data;

  if (!uid) {
    throw new HttpsError(
        "invalid-argument",
        "Missing required parameter: uid",
    );
  }

  try {
    await getAuth().deleteUser(uid);
    return {message: "Firebase Auth user deleted successfully."};
  } catch (error) {
    logger.error(
        "Error deleting Firebase Auth user:",
        error,
        {structuredData: true},
    );
    throw new HttpsError(
        "internal",
        "Failed to delete Firebase Auth user.",
    );
  }
});
