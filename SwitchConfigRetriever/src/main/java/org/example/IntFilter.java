package org.example;

import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import javax.swing.text.DocumentFilter;

public class IntFilter extends DocumentFilter {
    private boolean allowDot;

    public IntFilter(boolean allowDot) {
        this.allowDot = allowDot;
    }

    public void insertString(DocumentFilter.FilterBypass fb, int offset, String string, AttributeSet attr) throws BadLocationException {
        System.out.println("insertString");
        Document doc = fb.getDocument();
        StringBuilder sb = new StringBuilder();
        sb.append(doc.getText(0, doc.getLength()));
        sb.insert(offset, string);
        if (this.test(sb.toString())) {
            super.insertString(fb, offset, string, attr);
        }

    }

    private boolean test(String text) {
        char[] var2 = text.toCharArray();
        int var3 = var2.length;

        for(int var4 = 0; var4 < var3; ++var4) {
            char c = var2[var4];
            if (!Character.isDigit(c) && this.allowDot && c != '.') {
                return false;
            }
        }

        return true;
    }

    public void replace(DocumentFilter.FilterBypass fb, int offset, int length, String text, AttributeSet attrs) throws BadLocationException {
        System.out.println("replace");
        Document doc = fb.getDocument();
        StringBuilder sb = new StringBuilder();
        sb.append(doc.getText(0, doc.getLength()));
        sb.replace(offset, offset + length, text);
        if (this.test(sb.toString())) {
            super.replace(fb, offset, length, text, attrs);
        }

    }

    public void remove(DocumentFilter.FilterBypass fb, int offset, int length) throws BadLocationException {
        System.out.println("remove");
        Document doc = fb.getDocument();
        StringBuilder sb = new StringBuilder();
        sb.append(doc.getText(0, doc.getLength()));
        sb.delete(offset, offset + length);
        if (this.test(sb.toString())) {
            super.remove(fb, offset, length);
        }

    }
}
