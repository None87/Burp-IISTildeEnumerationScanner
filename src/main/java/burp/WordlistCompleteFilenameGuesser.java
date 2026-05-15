package burp;

import java.util.List;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Collections;

class WordlistCompleteFilenameGuesser extends Thread implements IIntruderPayloadGeneratorFactory {
	private final String fileNameWordlistSource;
	private final String fileExtWordlistSource;
	private final List<String> filesFound;
	private final List<String> dirsFound;
	private List<String> intruderPayloads;

	public WordlistCompleteFilenameGuesser(List<String> dirsFound, List<String> filesFound,
											String fileNameWordlistSource, String fileExtWordlistSource) {
		this.fileNameWordlistSource = fileNameWordlistSource;
		this.fileExtWordlistSource = fileExtWordlistSource;
		this.filesFound = filesFound;
		this.dirsFound = dirsFound;
	}

	public List<String> getPayloads() {
		return intruderPayloads;
	}

	@Override
	public String getGeneratorName() {
		return "IISTildeEnumeration - wordlist-based full filename guessing";
	}

	@Override
	public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
		return new IntruderPayloadGenerator(intruderPayloads);
	}

	@Override
	public void run() {
		intruderPayloads = new ArrayList<String>();
		List<String> elementsFound = Utils.buildElementList(dirsFound, filesFound);
		List<String> possibleFileNames = WordlistLoader.load(fileNameWordlistSource);
		List<String> possibleFileExts = WordlistLoader.load(fileExtWordlistSource);
		for (String name : possibleFileNames) {
			for (String elem : elementsFound) {
				// check if thread has been interrupted, and in case stop looping
				if (isInterrupted())
					return;
				List<String> matches = Utils.findMatches(elem, name, possibleFileExts);
				intruderPayloads.addAll(matches);
			}
		}

		intruderPayloads = new ArrayList<String>(new LinkedHashSet<>(intruderPayloads));
		Collections.sort(intruderPayloads);
	}
}
