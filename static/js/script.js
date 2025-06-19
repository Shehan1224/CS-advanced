document.addEventListener('DOMContentLoaded', function() {
    // Toggle between single and multi-coin analysis forms
    const analysisTypeRadios = document.querySelectorAll('input[name="analysis_type"]');
    const singleAnalysisDiv = document.getElementById('single-analysis');
    const multiAnalysisDiv = document.getElementById('multi-analysis');

    analysisTypeRadios.forEach(radio => {
        radio.addEventListener('change', function() {
            if (this.value === 'single') {
                singleAnalysisDiv.style.display = 'block';
                multiAnalysisDiv.style.display = 'none';
                document.getElementById('symbol').required = true;
                document.getElementById('coins').required = false;
            } else {
                singleAnalysisDiv.style.display = 'none';
                multiAnalysisDiv.style.display = 'block';
                document.getElementById('symbol').required = false;
                document.getElementById('coins').required = true;
            }
        });
    });

    // Initialize with single analysis visible
    singleAnalysisDiv.style.display = 'block';
    multiAnalysisDiv.style.display = 'none';

    // Auto-refresh functionality
    if (window.location.pathname.includes('single_analysis') || 
        window.location.pathname.includes('multi_analysis')) {
        setTimeout(() => {
            window.location.reload();
        }, 300000); // Refresh every 5 minutes
    }
});