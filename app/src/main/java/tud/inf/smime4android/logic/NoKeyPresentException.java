package tud.inf.smime4android.logic;

/**
 * Created by don on 09.11.15.
 */
public class NoKeyPresentException extends Exception {
    private Exception next;

    public NoKeyPresentException() {
        this.initCause((Throwable)null);
    }

    public NoKeyPresentException(String s) {
        super(s);
        this.initCause((Throwable)null);
    }

    public NoKeyPresentException(String s, Exception e) {
        super(s);
        this.next = e;
        this.initCause((Throwable)null);
    }

    public synchronized Exception getNextException() {
        return this.next;
    }

    public synchronized Throwable getCause() {
        return this.next;
    }

    public synchronized boolean setNextException(Exception ex) {
        Object theEnd;
        for(theEnd = this; theEnd instanceof NoKeyPresentException &&
                ((NoKeyPresentException)theEnd).next != null; theEnd = ((NoKeyPresentException)theEnd).next) {
            ;
        }

        if(theEnd instanceof NoKeyPresentException) {
            ((NoKeyPresentException)theEnd).next = ex;
            return true;
        } else {
            return false;
        }
    }

    public synchronized String toString() {
        String s = super.toString();
        Exception n = this.next;
        if(n == null) {
            return s;
        } else {
            StringBuffer sb = new StringBuffer(s == null?"":s);

            while(n != null) {
                sb.append(";\n  nested exception is:\n\t");
                if(n instanceof NoKeyPresentException) {
                    NoKeyPresentException nkpex = (NoKeyPresentException)n;
                    sb.append(nkpex.superToString());
                    n = nkpex.next;
                } else {
                    sb.append(n.toString());
                    n = null;
                }
            }

            return sb.toString();
        }
    }

    private final String superToString() {
        return super.toString();
    }
}
