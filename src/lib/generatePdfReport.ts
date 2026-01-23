import jsPDF from 'jspdf';
import type { Scan } from '@/types/database';
import { RISK_LEVEL_DESCRIPTIONS } from '@/lib/riskScoring';

/**
 * Generate a comprehensive PDF security report
 * Includes error handling and graceful degradation for missing data
 */
export function generatePdfReport(scan: Scan) {
  try {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    
    // Colors
    const primaryColor: [number, number, number] = [0, 255, 136];
    const dangerColor: [number, number, number] = [255, 71, 87];
    const warningColor: [number, number, number] = [255, 193, 7];
    const successColor: [number, number, number] = [0, 255, 136];
    const darkBg: [number, number, number] = [10, 15, 20];
    const cardBg: [number, number, number] = [20, 25, 35];
    const textColor: [number, number, number] = [255, 255, 255];
    const mutedColor: [number, number, number] = [140, 140, 140];

    // Helper function for safe text
    const safeText = (value: string | null | undefined, fallback: string = 'N/A'): string => {
      return value || fallback;
    };

    // Helper function to get hostname safely
    const getHostname = (url: string): string => {
      try {
        return new URL(url).hostname;
      } catch {
        return url || 'Unknown';
      }
    };

    // Helper function for risk color
    const getRiskColor = (level: string | null): [number, number, number] => {
      switch (level) {
        case 'low': return successColor;
        case 'medium': return warningColor;
        case 'high': 
        case 'critical': return dangerColor;
        default: return mutedColor;
      }
    };

    let yPos = 0;
    let currentPage = 1;

    // Function to check if we need a new page
    const checkPageBreak = (neededSpace: number): void => {
      if (yPos + neededSpace > pageHeight - 25) {
        doc.addPage();
        currentPage++;
        doc.setFillColor(...darkBg);
        doc.rect(0, 0, pageWidth, pageHeight, 'F');
        yPos = 20;
      }
    };

    // === PAGE 1: HEADER & SUMMARY ===
    
    // Background
    doc.setFillColor(...darkBg);
    doc.rect(0, 0, pageWidth, pageHeight, 'F');

    // Header bar
    doc.setFillColor(15, 20, 30);
    doc.rect(0, 0, pageWidth, 50, 'F');
    
    yPos = 20;
    
    // Logo/Title
    doc.setTextColor(...primaryColor);
    doc.setFontSize(26);
    doc.setFont('helvetica', 'bold');
    doc.text('SecureScan', 20, yPos + 5);
    
    doc.setTextColor(...mutedColor);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'normal');
    doc.text('Security Assessment Report', 20, yPos + 15);
    
    // Report metadata
    doc.setTextColor(...textColor);
    doc.setFontSize(9);
    const reportDate = new Date().toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
    const reportTime = new Date().toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
    });
    doc.text(`Generated: ${reportDate}`, pageWidth - 20, yPos + 5, { align: 'right' });
    doc.text(`at ${reportTime}`, pageWidth - 20, yPos + 12, { align: 'right' });

    yPos = 60;

    // === TARGET URL SECTION ===
    doc.setFillColor(...cardBg);
    doc.roundedRect(15, yPos, pageWidth - 30, 35, 3, 3, 'F');
    
    doc.setTextColor(...mutedColor);
    doc.setFontSize(9);
    doc.text('TARGET URL', 22, yPos + 12);
    
    doc.setTextColor(...textColor);
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    const hostname = getHostname(scan.target_url);
    doc.text(hostname, 22, yPos + 26);
    
    doc.setTextColor(...mutedColor);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.text(scan.target_url, pageWidth - 22, yPos + 26, { align: 'right' });

    yPos += 45;

    // === EXECUTIVE SUMMARY ===
    doc.setFillColor(...cardBg);
    doc.roundedRect(15, yPos, pageWidth - 30, 70, 3, 3, 'F');

    doc.setTextColor(...mutedColor);
    doc.setFontSize(9);
    doc.text('EXECUTIVE SUMMARY', 22, yPos + 12);

    // Risk Level Badge
    const riskColor = getRiskColor(scan.risk_level);
    doc.setFillColor(...riskColor);
    const riskText = (scan.risk_level || 'Unknown').toUpperCase();
    const riskWidth = doc.getTextWidth(riskText) * 1.5 + 16;
    doc.roundedRect(22, yPos + 18, riskWidth, 12, 2, 2, 'F');
    
    doc.setTextColor(...darkBg);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text(riskText, 30, yPos + 27);

    // Risk Score
    doc.setTextColor(...textColor);
    doc.setFontSize(36);
    doc.text(`${scan.risk_score ?? 0}`, pageWidth - 55, yPos + 40, { align: 'center' });
    
    doc.setTextColor(...mutedColor);
    doc.setFontSize(12);
    doc.setFont('helvetica', 'normal');
    doc.text('/100', pageWidth - 30, yPos + 40);
    doc.setFontSize(9);
    doc.text('Risk Score', pageWidth - 55, yPos + 50, { align: 'center' });

    // Risk Level Description
    const levelInfo = RISK_LEVEL_DESCRIPTIONS[scan.risk_level || 'medium'];
    doc.setTextColor(...textColor);
    doc.setFontSize(9);
    const descriptionLines = doc.splitTextToSize(levelInfo?.description || 'Security assessment complete.', 100);
    doc.text(descriptionLines, 22, yPos + 45);

    // Score bar
    doc.setFillColor(30, 35, 45);
    doc.roundedRect(22, yPos + 58, 110, 6, 2, 2, 'F');
    const scoreWidth = Math.max(Math.min((scan.risk_score ?? 0), 100), 2);
    doc.setFillColor(...riskColor);
    doc.roundedRect(22, yPos + 58, scoreWidth, 6, 2, 2, 'F');

    yPos += 80;

    // === SSL & HEADERS ROW ===
    const colWidth = (pageWidth - 35) / 2;
    
    // SSL Card
    doc.setFillColor(...cardBg);
    doc.roundedRect(15, yPos, colWidth, 60, 3, 3, 'F');

    doc.setTextColor(...mutedColor);
    doc.setFontSize(9);
    doc.text('SSL CERTIFICATE', 22, yPos + 12);

    const sslColor = scan.ssl_valid ? successColor : dangerColor;
    doc.setTextColor(...sslColor);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text(scan.ssl_valid ? '✓ Valid' : '✗ Invalid/Missing', 22, yPos + 28);

    doc.setTextColor(...mutedColor);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    
    let sslY = yPos + 40;
    if (scan.ssl_issuer) {
      doc.text(`Issuer: ${scan.ssl_issuer}`, 22, sslY);
      sslY += 10;
    }
    if (scan.ssl_expiry_date) {
      const expiryDate = new Date(scan.ssl_expiry_date).toLocaleDateString();
      doc.text(`Expires: ${expiryDate}`, 22, sslY);
    } else {
      doc.text('Expiry: Not available', 22, sslY);
    }

    // Headers Card
    const headersX = 20 + colWidth;
    doc.setFillColor(...cardBg);
    doc.roundedRect(headersX, yPos, colWidth, 60, 3, 3, 'F');

    doc.setTextColor(...mutedColor);
    doc.setFontSize(9);
    doc.text('SECURITY HEADERS', headersX + 7, yPos + 12);

    const headersScore = scan.headers_score ?? 0;
    const headersColor = headersScore >= 70 ? successColor :
                         headersScore >= 40 ? warningColor : dangerColor;
    
    doc.setTextColor(...headersColor);
    doc.setFontSize(28);
    doc.setFont('helvetica', 'bold');
    doc.text(`${headersScore}`, headersX + 7, yPos + 38);
    
    doc.setTextColor(...mutedColor);
    doc.setFontSize(14);
    doc.text('/100', headersX + 40, yPos + 38);

    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    const presentCount = scan.present_headers?.length || 0;
    const missingCount = scan.missing_headers?.length || 0;
    doc.text(`${presentCount} present, ${missingCount} missing`, headersX + 7, yPos + 52);

    yPos += 70;

    // === PRESENT HEADERS ===
    if (scan.present_headers && scan.present_headers.length > 0) {
      checkPageBreak(40);
      
      const presentHeight = Math.min(Math.ceil(scan.present_headers.length / 2) * 12 + 28, 60);
      doc.setFillColor(...cardBg);
      doc.roundedRect(15, yPos, pageWidth - 30, presentHeight, 3, 3, 'F');

      doc.setTextColor(...successColor);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.text('✓ PRESENT HEADERS', 22, yPos + 12);

      doc.setTextColor(...textColor);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'normal');
      
      let headerY = yPos + 24;
      scan.present_headers.forEach((header, i) => {
        const xOffset = i % 2 === 0 ? 22 : pageWidth / 2;
        if (i % 2 === 0 && i > 0) headerY += 12;
        if (headerY < yPos + presentHeight - 5) {
          doc.text(`• ${header}`, xOffset, headerY);
        }
      });

      yPos += presentHeight + 8;
    }

    // === MISSING HEADERS ===
    if (scan.missing_headers && scan.missing_headers.length > 0) {
      checkPageBreak(40);
      
      const missingHeight = Math.min(Math.ceil(scan.missing_headers.length / 2) * 12 + 28, 60);
      doc.setFillColor(...cardBg);
      doc.roundedRect(15, yPos, pageWidth - 30, missingHeight, 3, 3, 'F');

      doc.setTextColor(...warningColor);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.text('⚠ MISSING HEADERS (Action Required)', 22, yPos + 12);

      doc.setTextColor(...textColor);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'normal');
      
      let headerY = yPos + 24;
      scan.missing_headers.forEach((header, i) => {
        const xOffset = i % 2 === 0 ? 22 : pageWidth / 2;
        if (i % 2 === 0 && i > 0) headerY += 12;
        if (headerY < yPos + missingHeight - 5) {
          doc.text(`• ${header}`, xOffset, headerY);
        }
      });

      yPos += missingHeight + 8;
    }

    // === DETECTED TECHNOLOGIES ===
    if (scan.detected_technologies && scan.detected_technologies.length > 0) {
      checkPageBreak(40);
      
      const techHeight = Math.min(Math.ceil(scan.detected_technologies.length / 3) * 12 + 28, 50);
      doc.setFillColor(...cardBg);
      doc.roundedRect(15, yPos, pageWidth - 30, techHeight, 3, 3, 'F');

      doc.setTextColor(...mutedColor);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.text('DETECTED TECHNOLOGIES', 22, yPos + 12);

      doc.setTextColor(...textColor);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'normal');
      
      let techY = yPos + 24;
      scan.detected_technologies.forEach((tech, i) => {
        const col = i % 3;
        const xOffset = 22 + col * 55;
        if (col === 0 && i > 0) techY += 12;
        if (techY < yPos + techHeight - 5) {
          doc.text(`• ${tech}`, xOffset, techY);
        }
      });

      yPos += techHeight + 8;
    }

    // === SERVER INFO ===
    if (scan.server_info) {
      checkPageBreak(30);
      
      doc.setFillColor(...cardBg);
      doc.roundedRect(15, yPos, pageWidth - 30, 25, 3, 3, 'F');

      doc.setTextColor(...mutedColor);
      doc.setFontSize(9);
      doc.text('SERVER INFO', 22, yPos + 12);

      doc.setTextColor(...textColor);
      doc.setFontSize(10);
      doc.text(scan.server_info, 22, yPos + 20);

      yPos += 33;
    }

    // === SCAN METADATA ===
    checkPageBreak(40);
    
    doc.setFillColor(...cardBg);
    doc.roundedRect(15, yPos, pageWidth - 30, 30, 3, 3, 'F');

    doc.setTextColor(...mutedColor);
    doc.setFontSize(8);
    
    const scanDate = scan.completed_at 
      ? new Date(scan.completed_at).toLocaleString() 
      : new Date(scan.created_at).toLocaleString();
    const duration = scan.scan_duration_ms 
      ? `${(scan.scan_duration_ms / 1000).toFixed(1)}s` 
      : 'N/A';

    doc.text(`Scan ID: ${scan.id}`, 22, yPos + 12);
    doc.text(`Completed: ${scanDate}`, 22, yPos + 22);
    doc.text(`Duration: ${duration}`, pageWidth - 22, yPos + 12, { align: 'right' });
    doc.text(`Status: ${scan.status.toUpperCase()}`, pageWidth - 22, yPos + 22, { align: 'right' });

    yPos += 40;

    // === FOOTER ===
    const addFooter = () => {
      const footerY = pageHeight - 12;
      doc.setDrawColor(30, 35, 45);
      doc.line(15, footerY - 5, pageWidth - 15, footerY - 5);
      
      doc.setTextColor(...mutedColor);
      doc.setFontSize(7);
      doc.setFont('helvetica', 'normal');
      doc.text(
        'This report was generated by SecureScan. For informational purposes only. Not a substitute for professional security audit.',
        pageWidth / 2,
        footerY,
        { align: 'center' }
      );
      doc.text(
        `Page ${currentPage}`,
        pageWidth - 15,
        footerY,
        { align: 'right' }
      );
    };

    // Add footer to all pages
    const totalPages = doc.internal.pages.length - 1;
    for (let i = 1; i <= totalPages; i++) {
      doc.setPage(i);
      currentPage = i;
      addFooter();
    }

    // Generate filename
    const dateStr = new Date().toISOString().split('T')[0];
    const filename = `securescan-${hostname.replace(/\./g, '-')}-${dateStr}.pdf`;
    
    // Save the PDF
    doc.save(filename);
    
    return { success: true, filename };
  } catch (error) {
    console.error('PDF generation failed:', error);
    
    // Fallback: Create a simple text-based PDF
    try {
      const doc = new jsPDF();
      doc.setFontSize(16);
      doc.text('SecureScan Report', 20, 20);
      doc.setFontSize(12);
      doc.text(`Target: ${scan.target_url}`, 20, 35);
      doc.text(`Risk Level: ${scan.risk_level || 'Unknown'}`, 20, 45);
      doc.text(`Risk Score: ${scan.risk_score ?? 0}/100`, 20, 55);
      doc.text(`SSL Valid: ${scan.ssl_valid ? 'Yes' : 'No'}`, 20, 65);
      doc.text(`Headers Score: ${scan.headers_score ?? 0}/100`, 20, 75);
      doc.text(`Generated: ${new Date().toLocaleString()}`, 20, 90);
      doc.text('Note: Full report generation failed. This is a simplified version.', 20, 110);
      
      doc.save(`securescan-report-${Date.now()}.pdf`);
      return { success: true, filename: 'securescan-report.pdf', fallback: true };
    } catch (fallbackError) {
      console.error('Fallback PDF generation also failed:', fallbackError);
      return { success: false, error: 'Failed to generate PDF report' };
    }
  }
}
