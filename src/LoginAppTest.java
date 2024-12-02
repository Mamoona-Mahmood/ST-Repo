import org.junit.Test;
import org.mockito.Mockito;

import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class LoginAppTest {

    @Test
    public void testSuccessfulLogin() throws Exception {
        LoginApp app = Mockito.spy(new LoginApp());
        String email = "johndoe@example.com";
        String expectedName = "John Doe";
        doReturn(expectedName).when(app).authenticateUser(email);
        assertEquals("The user should be authenticated successfully.", expectedName, app.authenticateUser(email));
    }

    @Test
    public void testFailedLogin() throws Exception {
        LoginApp app = Mockito.spy(new LoginApp());
        String email = "nonexistent@example.com";
        doReturn(null).when(app).authenticateUser(email);
        assertNull("The user should not be authenticated.", app.authenticateUser(email));
    }

    @Test
    public void testEmptyEmail() throws Exception {
        LoginApp app = Mockito.spy(new LoginApp());
        String email = "";
        doReturn(null).when(app).authenticateUser(email);
        assertNull("The authentication should fail for an empty email.", app.authenticateUser(email));
    }
    @Test
    public void testSQLInjectionAttempt() throws Exception {
        LoginApp loginApp = new LoginApp();
        Method method = LoginApp.class.getDeclaredMethod("authenticateUser", String.class);
        method.setAccessible(true);
        String userName = (String) method.invoke(loginApp, "johndoe@example.com' OR '1'='1");
        assertNull("Authentication should fail for an SQL injection attempt.", userName);
    }
    @Test
    public void testDatabaseConnectionFailure() {
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/invalid_db", "root", "wrongpassword");
            fail("Expected a SQLException due to database connection failure");
        } catch (SQLException e) {
            assertTrue(e.getMessage().contains("Access denied"));
        }
    }
    @Test
    public void testInvalidPassword() throws Exception {
        LoginApp loginApp = new LoginApp();
        Method method = LoginApp.class.getDeclaredMethod("authenticateUser", String.class, String.class);
        method.setAccessible(true);

        String userName = (String) method.invoke(loginApp, "johndoe@example.com", "wrongpassword");
        assertNull("Authentication should fail for incorrect password.", userName);
    }


    @Test
    public void testEmptyPassword() throws Exception {
        LoginApp loginApp = new LoginApp();
        Method method = LoginApp.class.getDeclaredMethod("authenticateUser", String.class, String.class);
        method.setAccessible(true);

        String userName = (String) method.invoke(loginApp, "johndoe@example.com", "");
        assertNull("Authentication should fail for an empty password input.", userName);
    }
}
